import secrets
import string
from typing import List, Set


class PasswordGenerator:
    def __init__(self):
        self.password_history: List[str] = []
        self.max_history = 20

    def generate(
        self,
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = True
    ) -> str:
        if length < 8:
            length = 8
        if length > 64:
            length = 64

        charsets = []
        if use_uppercase:
            charsets.append(string.ascii_uppercase)
        if use_lowercase:
            charsets.append(string.ascii_lowercase)
        if use_digits:
            charsets.append(string.digits)
        if use_symbols:
            charsets.append('!@#$%^&*()_+-=[]{}|;:,.<>?')

        if not charsets:
            charsets = [string.ascii_letters + string.digits]

        all_chars = ''.join(charsets)

        if exclude_ambiguous:
            ambiguous = 'lI1O0'
            all_chars = ''.join(c for c in all_chars if c not in ambiguous)
            for i, charset in enumerate(charsets):
                charsets[i] = ''.join(c for c in charset if c not in ambiguous)

        while True:
            password_chars = []
            for charset in charsets:
                password_chars.append(secrets.choice(charset))

            remaining = length - len(password_chars)
            for _ in range(remaining):
                password_chars.append(secrets.choice(all_chars))

            for i in range(len(password_chars) - 1, 0, -1):
                j = secrets.randbelow(i + 1)
                password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

            password = ''.join(password_chars)

            if self._check_strength(password) >= 3:
                if password not in self.password_history:
                    self._add_to_history(password)
                    return password

    def _check_strength(self, password: str) -> int:
        score = 0
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            score += 1
        if len(set(password)) >= 8:
            score += 1

        common = ['password', '123456', 'qwerty', 'admin', 'letmein', 'welcome']
        if not any(c in password.lower() for c in common):
            score += 1

        return min(score, 10)

    def _add_to_history(self, password: str):
        self.password_history.append(password)
        if len(self.password_history) > self.max_history:
            self.password_history.pop(0)

    def is_duplicate(self, password: str) -> bool:
        return password in self.password_history

    def get_configuration_options(self) -> dict:
        return {
            'min_length': 8,
            'max_length': 64,
            'default_length': 16,
            'supports_uppercase': True,
            'supports_lowercase': True,
            'supports_digits': True,
            'supports_symbols': True,
            'supports_exclude_ambiguous': True
        }