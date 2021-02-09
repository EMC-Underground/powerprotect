import sys
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
