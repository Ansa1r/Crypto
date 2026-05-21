import secrets
import string
from typing import List, Dict, Any, Tuple
from pyzxcvbn import zxcvbn


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
            exclude_ambiguous: bool = True,
            min_score: int = 3
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

        attempts = 0
        max_attempts = 100

        while attempts < max_attempts:
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

            score, feedback = self.analyze_strength(password)

            if score >= min_score:
                if password not in self.password_history:
                    self._add_to_history(password)
                    return password

            attempts += 1

        password = self._generate_fallback(length, charsets, all_chars)
        return password

    def _generate_fallback(self, length: int, charsets: List[str], all_chars: str) -> str:
        password_chars = []
        for charset in charsets:
            password_chars.append(secrets.choice(charset))
        remaining = length - len(password_chars)
        for _ in range(remaining):
            password_chars.append(secrets.choice(all_chars))
        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
        return ''.join(password_chars)

    def analyze_strength(self, password: str, user_inputs: List[str] = None) -> Tuple[int, Dict[str, Any]]:
        if user_inputs is None:
            user_inputs = []

        result = zxcvbn(password, user_inputs=user_inputs)

        score = result['score']

        feedback = {
            'warning': result['feedback'].get('warning', ''),
            'suggestions': result['feedback'].get('suggestions', []),
            'crack_times_seconds': result['crack_times_seconds'],
            'guesses': result['guesses']
        }

        return score, feedback

    def is_strong_enough(self, password: str, min_score: int = 3, user_inputs: List[str] = None) -> Tuple[
        bool, Dict[str, Any]]:
        score, feedback = self.analyze_strength(password, user_inputs)
        is_strong = score >= min_score
        return is_strong, {
            'score': score,
            'is_strong': is_strong,
            'feedback': feedback,
            'required_score': min_score
        }

    def get_strength_label(self, score: int) -> str:
        if score == 0:
            return "Very Weak"
        elif score == 1:
            return "Weak"
        elif score == 2:
            return "Fair"
        elif score == 3:
            return "Strong"
        else:
            return "Very Strong"

    def get_strength_color(self, score: int) -> str:
        if score == 0:
            return "#d32f2f"
        elif score == 1:
            return "#f44336"
        elif score == 2:
            return "#ff9800"
        elif score == 3:
            return "#4caf50"
        else:
            return "#2e7d32"

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
            'supports_exclude_ambiguous': True,
            'min_score_required': 3,
            'max_score': 4
        }

    def suggest_improvements(self, password: str, user_inputs: List[str] = None) -> List[str]:
        _, feedback = self.analyze_strength(password, user_inputs)
        return feedback['suggestions']

    def batch_analyze(self, passwords: List[str]) -> List[Dict[str, Any]]:
        results = []
        for password in passwords:
            score, feedback = self.analyze_strength(password)
            results.append({
                'password': password[:4] + '...' if len(password) > 8 else password,
                'score': score,
                'warning': feedback['warning'],
                'crack_time': feedback['crack_times_seconds']
            })
        return results

    def generate_with_constraints(
            self,
            length: int = 16,
            must_contain: List[str] = None,
            must_not_contain: List[str] = None,
            min_score: int = 3
    ) -> str:
        if must_contain is None:
            must_contain = []
        if must_not_contain is None:
            must_not_contain = []

        attempts = 0
        max_attempts = 200

        while attempts < max_attempts:
            password = self.generate(length=length, min_score=min_score)

            valid = True
            for required in must_contain:
                if required not in password:
                    valid = False
                    break

            if valid:
                for forbidden in must_not_contain:
                    if forbidden in password:
                        valid = False
                        break

            if valid:
                return password

            attempts += 1

        return self.generate(length=length, min_score=min_score)