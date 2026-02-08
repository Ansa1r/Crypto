from src.database.db import init_db, DB_PATH


def test_database_created():
    init_db()
    assert DB_PATH.exists()
