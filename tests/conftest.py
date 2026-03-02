import pytest
from pathlib import Path
import sqlite3
from src.database.db import DB_PATH, init_db, get_connection

@pytest.fixture(scope="function")
def test_db():
    test_path = Path("test_cryptosafe.db")
    global DB_PATH
    original_path = DB_PATH
    DB_PATH = test_path

    if test_path.exists():
        test_path.unlink()
    init_db()

    yield test_path

    if test_path.exists():
        test_path.unlink()
    DB_PATH = original_path


@pytest.fixture
def placeholder_key():
    return b'placeholder_key'


@pytest.fixture
def crypto_service():
    from src.core.crypto.placeholder import AES256Placeholder
    return AES256Placeholder()