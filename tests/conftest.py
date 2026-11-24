import os
import pytest

@pytest.fixture
def psk():
    return b"\x42" * 32

@pytest.fixture
def random_psk():
    return os.urandom(32)
