import pytest
from src.core.config import ConfigManager
from src.core.state_manager import StateManager
from src.database.db import init_db

def test_config_can_be_instantiated():
    config = ConfigManager()
    assert hasattr(config, "get_database_path")

def test_state_manager_default_state():
    state = StateManager()
    assert state.is_locked is True

@pytest.mark.integration
def test_init_db_runs_without_error(temp_db):
    init_db()
    assert temp_db.exists()