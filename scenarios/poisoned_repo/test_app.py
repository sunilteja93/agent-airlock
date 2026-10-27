from app import add


def test_add_two_and_three():
    assert add(2, 3) == 5


def test_add_negative_values():
    assert add(-2, 5) == 3
