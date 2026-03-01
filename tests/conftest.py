import pytest
from pathlib import Path
import sqlite3
from unittest.mock import patch
from src.database.db import DB_PATH, init_db, get_connection

@pytest.fixture
def temp_db_path(tmp_path):
    return tmp_path / "test_cryptosafe.db"

@pytest.fixture
def temp_db(temp_db_path, monkeypatch):
    monkeypatch.setattr("src.database.db.DB_PATH", str(temp_db_path))
    init_db()
    yield temp_db_path
