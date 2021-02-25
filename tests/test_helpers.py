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
    assert e_info is not None

def test_return_value_class():
    return_value = helpers.ReturnValue()
    assert return_value.success is None
    assert return_value.fail_msg is None
    assert return_value.status_code is None
    assert return_value.response is None
