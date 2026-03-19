import re
import secrets
import string
from typing import List, Tuple, Set


class PasswordValidator:
    def __init__(self, config=None):
        self.config = config or {}
        self.min_length = self.config.get('min_length', 12)
        self.require_upper = self.config.get('require_upper', True)
        self.require_lower = self.config.get('require_lower', True)
        self.require_digit = self.config.get('require_digit', True)
        self.require_special = self.config.get('require_special', True)
        self.common_passwords = self._load_common_passwords()

    def validate(self, password: str) -> Tuple[bool, List[str]]:
        errors = []

        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters")

        if self.require_upper and not re.search(r'[A-Z]', password):
            errors.append("Must contain uppercase letter")

        if self.require_lower and not re.search(r'[a-z]', password):
            errors.append("Must contain lowercase letter")

        if self.require_digit and not re.search(r'\d', password):
            errors.append("Must contain digit")

        if self.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Must contain special character")

        if password.lower() in self.common_passwords:
            errors.append("Password is too common")

        if self._is_sequential(password):
            errors.append("Contains sequential characters")

        if self._is_repetitive(password):
            errors.append("Contains too many repeated characters")

        return len(errors) == 0, errors

    def _is_sequential(self, password: str) -> bool:
        password_lower = password.lower()
        sequences = [
            'abcdefghijklmnopqrstuvwxyz',
            '0123456789',
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm'
        ]
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i + 3] in password_lower:
                    return True
        return False

    def _is_repetitive(self, password: str, max_repeat: int = 3) -> bool:
        for i in range(len(password) - max_repeat + 1):
            if len(set(password[i:i + max_repeat])) == 1:
                return True
        return False

    def _load_common_passwords(self) -> Set[str]:
        return {
            'password', 'password123', '123456', '12345678', '123456789',
            'qwerty', 'qwerty123', 'admin', 'admin123', 'letmein',
            'welcome', 'monkey', 'dragon', 'football', 'baseball',
            'master', 'superman', 'batman', 'starwars', 'iloveyou',
            'trustno1', 'princess', 'sunshine', 'whatever', 'abc123'
        }

    def generate_strong_password(self, length: int = 16) -> str:
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()"

        all_chars = lowercase + uppercase + digits + special

        while True:
            password = []
            if self.require_lower:
                password.append(secrets.choice(lowercase))
            if self.require_upper:
                password.append(secrets.choice(uppercase))
            if self.require_digit:
                password.append(secrets.choice(digits))
            if self.require_special:
                password.append(secrets.choice(special))

            remaining = length - len(password)
            password.extend(secrets.choice(all_chars) for _ in range(remaining))
            secrets.SystemRandom().shuffle(password)

            result = ''.join(password)
            valid, _ = self.validate(result)
            if valid:
                return result

    def calculate_strength(self, password: str) -> Tuple[int, str]:
        score = 0
        feedback = []

        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
        else:
            feedback.append("Too short")

        if re.search(r'[A-Z]', password):
            score += 15
        else:
            feedback.append("Add uppercase")

        if re.search(r'[a-z]', password):
            score += 15
        else:
            feedback.append("Add lowercase")

        if re.search(r'\d', password):
            score += 15
        else:
            feedback.append("Add digits")

        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 20
        else:
            feedback.append("Add special chars")

        if len(set(password)) > len(password) * 0.7:
            score += 10
        else:
            feedback.append("More variety")

        if score >= 80:
            strength = "Strong"
        elif score >= 50:
            strength = "Medium"
        else:
            strength = "Weak"

        return score, strength