from random import choice
from string import ascii_letters

import pytest


@pytest.fixture()
def random_string():
    return lambda: ''.join(choice(ascii_letters) for _ in range(10))
