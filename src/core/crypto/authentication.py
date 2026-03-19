import time
from typing import Optional, Dict
from dataclasses import dataclass
from enum import Enum


class AuthResult(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    LOCKED = "locked"
    EXPIRED = "expired"


@dataclass
class SessionInfo:
    username: str
    login_time: float
    last_activity: float
    failed_attempts: int
    ip_address: Optional[str] = None
    device_id: Optional[str] = None


class AuthenticationManager:
    def __init__(self, max_attempts: int = 5, lockout_duration: int = 300):
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self._failed_attempts: Dict[str, list] = {}
        self._locked_until: Dict[str, float] = {}
        self._sessions: Dict[str, SessionInfo] = {}

    def authenticate(self, username: str, password: str, verifier) -> AuthResult:
        if self.is_locked(username):
            return AuthResult.LOCKED

        if verifier.verify(username, password):
            self._reset_attempts(username)
            return AuthResult.SUCCESS
        else:
            self._record_failed_attempt(username)
            return AuthResult.FAILED

    def _record_failed_attempt(self, username: str):
        now = time.time()
        if username not in self._failed_attempts:
            self._failed_attempts[username] = []

        self._failed_attempts[username].append(now)
        self._failed_attempts[username] = [
            t for t in self._failed_attempts[username]
            if now - t < 3600
        ]

        if len(self._failed_attempts[username]) >= self.max_attempts:
            self._locked_until[username] = now + self.lockout_duration

    def _reset_attempts(self, username: str):
        if username in self._failed_attempts:
            del self._failed_attempts[username]
        if username in self._locked_until:
            del self._locked_until[username]

    def is_locked(self, username: str) -> bool:
        if username not in self._locked_until:
            return False
        if time.time() >= self._locked_until[username]:
            del self._locked_until[username]
            return False
        return True

    def get_lockout_time(self, username: str) -> float:
        if username not in self._locked_until:
            return 0
        remaining = self._locked_until[username] - time.time()
        return max(0, remaining)

    def get_failed_attempts(self, username: str) -> int:
        if username not in self._failed_attempts:
            return 0
        now = time.time()
        recent = [t for t in self._failed_attempts[username] if now - t < 3600]
        return len(recent)


class SessionManager:
    def __init__(self, session_timeout: int = 3600, inactivity_timeout: int = 900):
        self.session_timeout = session_timeout
        self.inactivity_timeout = inactivity_timeout
        self.current_session: Optional[SessionInfo] = None

    def create_session(self, username: str, ip_address: str = None, device_id: str = None) -> bool:
        now = time.time()
        self.current_session = SessionInfo(
            username=username,
            login_time=now,
            last_activity=now,
            failed_attempts=0,
            ip_address=ip_address,
            device_id=device_id
        )
        return True

    def destroy_session(self):
        self.current_session = None

    def update_activity(self):
        if self.current_session:
            self.current_session.last_activity = time.time()

    def is_valid(self) -> bool:
        if not self.current_session:
            return False

        now = time.time()

        if now - self.current_session.login_time > self.session_timeout:
            self.destroy_session()
            return False

        if now - self.current_session.last_activity > self.inactivity_timeout:
            self.destroy_session()
            return False

        return True

    def get_session_info(self) -> Optional[dict]:
        if not self.current_session:
            return None
        return {
            'username': self.current_session.username,
            'login_time': self.current_session.login_time,
            'last_activity': self.current_session.last_activity,
            'duration': time.time() - self.current_session.login_time,
            'inactive': time.time() - self.current_session.last_activity
        }

    def touch(self):
        self.update_activity()


class ExponentialBackoff:
    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.attempts = 0
        self.last_attempt = 0

    def get_delay(self) -> float:
        if self.attempts == 0:
            return 0

        delay = min(
            self.base_delay * (2 ** (self.attempts - 1)),
            self.max_delay
        )

        elapsed = time.time() - self.last_attempt
        remaining = max(0, delay - elapsed)

        return remaining

    def record_attempt(self):
        self.attempts += 1
        self.last_attempt = time.time()

    def reset(self):
        self.attempts = 0
        self.last_attempt = 0

    def can_attempt(self) -> bool:
        return self.get_delay() == 0