import re
from typing import Tuple, List


class PasswordValidator:
    def __init__(self):
        self.min_length = 12
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_digits = True
        self.require_symbols = True
        self.common_passwords = {
            'password', 'password123', '123456', '12345678', '123456789',
            'qwerty', 'qwerty123', 'abc123', 'admin', 'letmein', 'welcome',
            'monkey', 'dragon', 'master', 'football', 'baseball', 'login',
            'passw0rd', 'password1', '12345', '1234567', '1234567890',
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx', 'q1w2e3r4',
            'admin123', 'root', 'toor', '123123', '654321', '987654321',
            'mypassword', 'pass123', 'hello', 'iloveyou', 'whatever'
        }

    def validate(self, password: str) -> Tuple[bool, List[str]]:
        errors = []

        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")

        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")

        if self.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")

        if self.require_digits and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")

        if self.require_symbols and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")

        password_lower = password.lower()
        for common in self.common_passwords:
            if common in password_lower:
                errors.append("Password contains a common or easily guessable pattern")
                break

        return len(errors) == 0, errors

    def get_strength_score(self, password: str) -> int:
        score = 0

        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1

        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1

        if len(set(password)) >= 8:
            score += 1

        password_lower = password.lower()
        is_common = False
        for common in self.common_passwords:
            if common in password_lower:
                is_common = True
                break
        if not is_common:
            score += 1

        return min(score, 10)

    def get_strength_label(self, score: int) -> str:
        if score <= 2:
            return "Very Weak"
        elif score <= 4:
            return "Weak"
        elif score <= 6:
            return "Moderate"
        elif score <= 8:
            return "Strong"
        else:
            return "Very Strong"