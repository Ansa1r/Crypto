import json
import time
from typing import Optional, Dict, List, Tuple
from enum import Enum
from src.core.crypto.mfa_providers import (
    MFAProvider, MFAConfig, MFAType, MFAStatus,
    TOTPProvider, HOTPProvider, BackupCodeProvider,
    SMSProvider, EmailProvider
)


class MFAManager:
    def __init__(self, db_path=None):
        self.db_path = db_path
        self._providers = {}
        self._active_provider = None
        self._mfa_enabled = False
        self._mfa_status = MFAStatus.DISABLED
        self._pending_setup = None

    def _load_config(self) -> Dict:
        if not self.db_path:
            return {}

        try:
            from src.database.db import get_setting
            config_json = get_setting('mfa_config', self.db_path)
            if config_json:
                return json.loads(config_json)
        except Exception:
            pass

        return {}

    def _save_config(self, config: Dict):
        if not self.db_path:
            return

        try:
            from src.database.db import set_setting
            set_setting('mfa_config', json.dumps(config), 'json', self.db_path)
        except Exception:
            pass

    def _create_provider(self, mfa_type: MFAType, config_data: Dict) -> MFAProvider:
        config = MFAConfig(
            mfa_type=mfa_type,
            enabled=config_data.get('enabled', False),
            secret=config_data.get('secret'),
            backup_codes=config_data.get('backup_codes'),
            phone_number=config_data.get('phone_number'),
            email=config_data.get('email'),
            counter=config_data.get('counter', 0),
            lockout_until=config_data.get('lockout_until'),
            failed_attempts=config_data.get('failed_attempts', 0),
            max_attempts=config_data.get('max_attempts', 5),
            lockout_duration=config_data.get('lockout_duration', 300)
        )

        if mfa_type == MFAType.TOTP:
            return TOTPProvider(config)
        elif mfa_type == MFAType.HOTP:
            return HOTPProvider(config)
        elif mfa_type == MFAType.BACKUP_CODE:
            return BackupCodeProvider(config)
        elif mfa_type == MFAType.SMS:
            return SMSProvider(config)
        elif mfa_type == MFAType.EMAIL:
            return EmailProvider(config)
        else:
            raise ValueError(f"Unknown MFA type: {mfa_type}")

    def enable_mfa(self, mfa_type: MFAType, **kwargs) -> Dict:
        config_data = {
            'enabled': False,
            'mfa_type': mfa_type.value
        }

        if mfa_type == MFAType.SMS and 'phone_number' in kwargs:
            config_data['phone_number'] = kwargs['phone_number']
        elif mfa_type == MFAType.EMAIL and 'email' in kwargs:
            config_data['email'] = kwargs['email']

        provider = self._create_provider(mfa_type, config_data)
        setup_data = provider.get_setup_data()

        self._pending_setup = {
            'mfa_type': mfa_type,
            'config_data': config_data,
            'setup_data': setup_data,
            'created_at': time.time()
        }

        return setup_data

    def verify_setup(self, code: str) -> bool:
        if not self._pending_setup:
            return False

        mfa_type = self._pending_setup['mfa_type']
        config_data = self._pending_setup['config_data']

        provider = self._create_provider(mfa_type, config_data)

        if mfa_type == MFAType.SMS or mfa_type == MFAType.EMAIL:
            provider.send_code()
            return provider.verify_code(code)
        else:
            return provider.verify_code(code)

    def complete_setup(self, code: str) -> bool:
        if not self.verify_setup(code):
            return False

        if not self._pending_setup:
            return False

        mfa_type = self._pending_setup['mfa_type']
        config_data = self._pending_setup['setup_data']

        provider = self._create_provider(mfa_type, config_data)

        if mfa_type == MFAType.BACKUP_CODE:
            backup_codes = config_data.get('backup_codes', [])
            config_data['backup_codes'] = backup_codes

        config_data['enabled'] = True

        self._providers[mfa_type.value] = config_data
        self._active_provider = mfa_type.value
        self._mfa_enabled = True
        self._mfa_status = MFAStatus.ENABLED

        self._save_config({
            'enabled': True,
            'active_provider': mfa_type.value,
            'providers': {k: v for k, v in self._providers.items()}
        })

        self._pending_setup = None

        return True

    def verify_mfa(self, code: str) -> Tuple[bool, str]:
        if not self._mfa_enabled:
            return True, "MFA not enabled"

        if not self._active_provider or self._active_provider not in self._providers:
            return False, "No active MFA provider"

        provider_config = self._providers[self._active_provider]
        mfa_type = MFAType(provider_config.get('mfa_type', 'totp'))

        provider = self._create_provider(mfa_type, provider_config)

        if provider.verify_code(code):
            return True, "MFA verification successful"
        else:
            return False, "Invalid verification code"

    def generate_backup_codes(self) -> List[str]:
        backup_provider = self._create_provider(MFAType.BACKUP_CODE, {})
        backup_provider.generate_secret()

        setup_data = backup_provider.get_setup_data()
        backup_codes = setup_data.get('backup_codes', [])

        self._providers['backup_code'] = {
            'mfa_type': 'backup_code',
            'enabled': True,
            'backup_codes': backup_codes
        }

        self._save_config({
            'enabled': self._mfa_enabled,
            'active_provider': self._active_provider,
            'providers': self._providers
        })

        return backup_codes

    def verify_backup_code(self, code: str) -> bool:
        if 'backup_code' not in self._providers:
            return False

        provider_config = self._providers['backup_code']
        provider = self._create_provider(MFAType.BACKUP_CODE, provider_config)

        return provider.verify_code(code)

    def disable_mfa(self):
        self._mfa_enabled = False
        self._mfa_status = MFAStatus.DISABLED
        self._active_provider = None
        self._providers = {}

        self._save_config({
            'enabled': False,
            'active_provider': None,
            'providers': {}
        })

    def get_mfa_status(self) -> Dict:
        return {
            'enabled': self._mfa_enabled,
            'status': self._mfa_status.value,
            'active_provider': self._active_provider,
            'available_providers': [p.value for p in MFAType]
        }

    def get_setup_status(self) -> Dict:
        if self._pending_setup:
            return {
                'has_pending_setup': True,
                'mfa_type': self._pending_setup['mfa_type'].value,
                'created_at': self._pending_setup['created_at'],
                'setup_data': self._pending_setup.get('setup_data', {})
            }

        return {
            'has_pending_setup': False
        }

    def load_from_storage(self):
        config = self._load_config()

        if config.get('enabled'):
            self._mfa_enabled = True
            self._mfa_status = MFAStatus.ENABLED
            self._active_provider = config.get('active_provider')
            self._providers = config.get('providers', {})
        else:
            self._mfa_enabled = False
            self._mfa_status = MFAStatus.DISABLED
            self._active_provider = None
            self._providers = {}

    def get_hooks(self) -> Dict:
        return {
            'pre_login': self._pre_login_hook,
            'post_login': self._post_login_hook,
            'pre_unlock': self._pre_unlock_hook,
            'post_unlock': self._post_unlock_hook,
            'on_failed_attempt': self._on_failed_attempt_hook
        }

    def _pre_login_hook(self, context: Dict) -> Tuple[bool, str]:
        if self._mfa_enabled and self._active_provider:
            return True, "MFA required"
        return True, "No MFA required"

    def _post_login_hook(self, context: Dict) -> Tuple[bool, str]:
        return True, "Login successful"

    def _pre_unlock_hook(self, context: Dict) -> Tuple[bool, str]:
        if self._mfa_enabled and self._active_provider:
            return True, "MFA verification required for unlock"
        return True, "No MFA required for unlock"

    def _post_unlock_hook(self, context: Dict) -> Tuple[bool, str]:
        return True, "Unlock successful"

    def _on_failed_attempt_hook(self, context: Dict) -> Tuple[bool, str]:
        if 'failed_attempts' in context and context['failed_attempts'] >= 3:
            return False, "Too many failed attempts"
        return True, "Attempt recorded"