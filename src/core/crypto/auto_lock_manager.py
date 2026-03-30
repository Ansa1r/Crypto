import time
import threading
from typing import Optional, Callable, Dict
from enum import Enum
from dataclasses import dataclass
from datetime import datetime


class LockReason(Enum):
    INACTIVITY = "inactivity"
    MANUAL = "manual"
    APPLICATION_EXIT = "application_exit"
    SYSTEM_SLEEP = "system_sleep"
    SCREEN_LOCK = "screen_lock"
    MINIMIZE = "minimize"
    BACKGROUND = "background"
    TIMEOUT = "timeout"


@dataclass
class LockEvent:
    reason: LockReason
    timestamp: float
    details: Optional[str] = None


class AutoLockManager:
    def __init__(self, key_manager=None, config=None):
        self.key_manager = key_manager
        self.config = config or {}

        self.auto_lock_enabled = self.config.get('auto_lock_enabled', True)
        self.inactivity_timeout = self.config.get('inactivity_timeout', 3600)
        self.lock_on_minimize = self.config.get('lock_on_minimize', False)
        self.lock_on_background = self.config.get('lock_on_background', False)
        self.lock_on_system_sleep = self.config.get('lock_on_system_sleep', True)
        self.lock_on_screen_lock = self.config.get('lock_on_screen_lock', True)

        self._last_activity = time.time()
        self._lock_timer = None
        self._is_locked = False
        self._listeners = []
        self._lock_history = []
        self._lock_thread = None
        self._running = False

        self._setup_lock_timer()

    def _setup_lock_timer(self):
        if self._lock_timer:
            self._lock_timer.cancel()

        if self.auto_lock_enabled and self.inactivity_timeout > 0:
            self._lock_timer = threading.Timer(self.inactivity_timeout, self._check_inactivity)
            self._lock_timer.daemon = True
            self._lock_timer.start()

    def _check_inactivity(self):
        if not self.auto_lock_enabled:
            return

        if self._is_locked:
            return

        now = time.time()
        if now - self._last_activity >= self.inactivity_timeout:
            self.lock(LockReason.INACTIVITY, f"No activity for {self.inactivity_timeout} seconds")
        else:
            remaining = self.inactivity_timeout - (now - self._last_activity)
            if remaining > 0:
                self._lock_timer = threading.Timer(remaining, self._check_inactivity)
                self._lock_timer.daemon = True
                self._lock_timer.start()

    def update_activity(self):
        self._last_activity = time.time()
        self._setup_lock_timer()

    def lock(self, reason: LockReason = LockReason.MANUAL, details: str = None) -> bool:
        if self._is_locked:
            return False

        self._is_locked = True

        lock_event = LockEvent(
            reason=reason,
            timestamp=time.time(),
            details=details
        )
        self._lock_history.append(lock_event)

        if len(self._lock_history) > 100:
            self._lock_history = self._lock_history[-100:]

        if self.key_manager:
            self.key_manager.logout(clear_cache=True)

        self._notify_listeners('locked', lock_event)

        return True

    def unlock(self) -> bool:
        if not self._is_locked:
            return False

        self._is_locked = False
        self._last_activity = time.time()
        self._setup_lock_timer()

        self._notify_listeners('unlocked', {'timestamp': time.time()})

        return True

    def is_locked(self) -> bool:
        return self._is_locked

    def register_listener(self, event_type: str, callback: Callable):
        self._listeners.append((event_type, callback))

    def _notify_listeners(self, event_type: str, data):
        for evt_type, callback in self._listeners:
            if evt_type == event_type or evt_type == '*':
                try:
                    callback(event_type, data)
                except Exception:
                    pass

    def on_activity_detected(self):
        if not self._is_locked:
            self.update_activity()

    def on_window_minimized(self):
        if self.lock_on_minimize and not self._is_locked:
            self.lock(LockReason.MINIMIZE, "Window minimized")

    def on_window_background(self):
        if self.lock_on_background and not self._is_locked:
            self.lock(LockReason.BACKGROUND, "Application sent to background")

    def on_system_sleep(self):
        if self.lock_on_system_sleep and not self._is_locked:
            self.lock(LockReason.SYSTEM_SLEEP, "System entering sleep mode")

    def on_screen_lock(self):
        if self.lock_on_screen_lock and not self._is_locked:
            self.lock(LockReason.SCREEN_LOCK, "Screen locked")

    def get_lock_history(self, limit: int = 10) -> list:
        return [
            {
                'reason': event.reason.value,
                'timestamp': datetime.fromtimestamp(event.timestamp).isoformat(),
                'details': event.details
            }
            for event in self._lock_history[-limit:]
        ]

    def get_status(self) -> Dict:
        return {
            'is_locked': self._is_locked,
            'auto_lock_enabled': self.auto_lock_enabled,
            'inactivity_timeout': self.inactivity_timeout,
            'seconds_since_activity': time.time() - self._last_activity,
            'last_activity': datetime.fromtimestamp(self._last_activity).isoformat(),
            'lock_on_minimize': self.lock_on_minimize,
            'lock_on_background': self.lock_on_background,
            'lock_on_system_sleep': self.lock_on_system_sleep,
            'lock_on_screen_lock': self.lock_on_screen_lock,
            'total_lock_events': len(self._lock_history)
        }

    def update_config(self, config: Dict):
        self.auto_lock_enabled = config.get('auto_lock_enabled', self.auto_lock_enabled)
        self.inactivity_timeout = config.get('inactivity_timeout', self.inactivity_timeout)
        self.lock_on_minimize = config.get('lock_on_minimize', self.lock_on_minimize)
        self.lock_on_background = config.get('lock_on_background', self.lock_on_background)
        self.lock_on_system_sleep = config.get('lock_on_system_sleep', self.lock_on_system_sleep)
        self.lock_on_screen_lock = config.get('lock_on_screen_lock', self.lock_on_screen_lock)

        if not self._is_locked:
            self._setup_lock_timer()

    def start(self):
        self._running = True

    def stop(self):
        self._running = False
        if self._lock_timer:
            self._lock_timer.cancel()