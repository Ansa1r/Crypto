from pathlib import Path


class ConfigManager:

    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent.parent
        self.db_path = self.base_dir / "cryptosafe.db"
        self.environment = "development"

    def get_database_path(self) -> Path:
        return self.db_path

    def is_production(self) -> bool:
        return self.environment == "production"
