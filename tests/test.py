import sys
import requests
from unittest import mock
import pytest
sys.path.insert(0, '../powerprotect/')
import powerprotect

ppdm = powerprotect.Ppdm(server="localhost", token="abc123")


def test_init_good_with_token():
    test_ppdm = powerprotect.Ppdm(server="localhost", token="123abc")
    assert test_ppdm.headers == {'Content-Type': 'application/json',
                                 'Authorization': '123abc'}
    assert test_ppdm.server == "localhost"


def test_init_good_with_password_no_user():
    test_ppdm = powerprotect.Ppdm(server="localhost", password="testme")
    assert test_ppdm.headers == {'Content-Type': 'application/json'}
    assert test_ppdm.server == "localhost"
    assert test_ppdm.username == "admin"
    assert test_ppdm._Ppdm__password == "testme"


def test_init_good_with_password_with_user():
    test_ppdm = powerprotect.Ppdm(server="localhost", password="testme",
                                  username="testuser")
    assert test_ppdm.headers == {'Content-Type': 'application/json'}
    assert test_ppdm.server == "localhost"
    assert test_ppdm.username == "testuser"
    assert test_ppdm._Ppdm__password == "testme"


def test_init_bad():
    with pytest.raises(Exception) as e_info:
        test_ppdm = powerprotect.Ppdm()
        del test_ppdm
    assert e_info is not None


@mock.patch('powerprotect.ppdm.requests.get')
def test_rest_get_good(mock_get):
    mock_get.return_value.ok = True
    response = ppdm._Ppdm__rest_get("/valid-uri")
    assert response.ok is True


@mock.patch('powerprotect.ppdm.requests.get')
def test_rest_get_bad(mock_turd):
    mock_response = mock.Mock()
    http_error = requests.exceptions.HTTPError()
    mock_response.raise_for_status.side_effect = http_error
    mock_turd.return_value = mock_response
    mock_turd.return_value.ok = False
    response = ppdm._Ppdm__rest_get("/valid-uri")
    assert response.ok is False
