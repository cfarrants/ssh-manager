"""Tests never read or write the real user's OS credential store."""
import pytest
from ssh_manager import credentials


@pytest.fixture(autouse=True)
def isolated_credential_store(monkeypatch):
    class MemoryKeyring:
        def __init__(self):self.values={}
        def get_password(self,service,user):return self.values.get((service,user))
        def set_password(self,service,user,password):self.values[service,user]=password
    backend=MemoryKeyring()
    monkeypatch.setattr(credentials,'_backend',lambda:backend)
    return backend
