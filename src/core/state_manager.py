class StateManager:

    def __init__(self):
        self.is_locked = True
        self.current_user = None
        self.clipboard_data = None
        self.clipboard_timer = None
        self.inactivity_timer = None

    def lock(self):
        self.is_locked = True

    def unlock(self, user: str):
        self.is_locked = False
        self.current_user = user
