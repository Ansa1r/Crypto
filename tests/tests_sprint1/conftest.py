import pytest
from pathlib import Path
import sqlite3
import tempfile
import shutil
from src.database.db import init_db, get_connection
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.parameter_validator import ParameterValidator
from src.core.crypto.password_validator import PasswordValidator


@pytest.fixture(scope="function")
def test_db():
    temp_dir = tempfile.mkdtemp()
    test_path = Path(temp_dir) / "test_cryptosafe.db"

    original_db_path = None
    try:
        from src.database import db
        original_db_path = db.DB_PATH
        db.DB_PATH = test_path

        if test_path.exists():
            test_path.unlink()

        init_db()

        yield test_path
    finally:
        if test_path.exists():
            test_path.unlink()
        if original_db_path:
            from src.database import db
            db.DB_PATH = original_db_path
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def placeholder_key():
    return b'placeholder_key_16_bytes'


@pytest.fixture
def crypto_service():
    from src.core.crypto.placeholder import AES256Placeholder
    return AES256Placeholder()


@pytest.fixture
def key_derivation():
    return KeyDerivation()


@pytest.fixture
def parameter_validator():
    return ParameterValidator()


@pytest.fixture
def password_validator():
    return PasswordValidator()


@pytest.fixture
def test_password():
    return "TestPassword123!"


@pytest.fixture
def weak_password():
    return "weak"


@pytest.fixture
def strong_password():
    return "Str0ngP@ssw0rd123!WithLength"


@pytest.fixture
def common_password():
    return "password123"


@pytest.fixture
def sample_argon2_params():
    return {
        'time_cost': 3,
        'memory_cost': 65536,
        'parallelism': 4
    }