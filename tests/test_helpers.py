import sys
import pytest
sys.path.insert(0, '../powerprotect/')
from powerprotect import helpers

body1 = {'key': 'value', 'key1': 'value1', 'additional': 'value'}
body2 = {'key': 'value', 'key1': 'value1'}
body3 = {'nomatch': 'nothere'}
invalid = 1


def test_body_match_valid_input_match():
    output = helpers._body_match(body1, body2)
    assert output is True


def test_body_match_valid_input_no_match():
    output = helpers._body_match(body1, body3)
    assert output is False


def test_body_match_invalid_input():
    with pytest.raises(Exception) as e_info:
        output = helpers._body_match(invalid, invalid)
        del output
    assert e_info is not None


def test_return_body_class():
    return_body = helpers.ReturnBody()
    assert type(return_body.success) is bool
    assert type(return_body.msg) is str
    assert type(return_body.status_code) is int
    assert type(return_body.response) is dict
