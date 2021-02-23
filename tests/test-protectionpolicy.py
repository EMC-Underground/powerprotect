import sys
from unittest import mock, TestCase
import pytest
sys.path.insert(0, '../powerprotect/')
import powerprotect


class TestInit(TestCase):

    def setUp(self):
        patcher_get_policy = mock.patch(
            'powerprotect.protectionpolicy.ProtectionPolicy.get_policy')
        self.mock_get_policy = patcher_get_policy.start()
        patcher_login = mock.patch(
            'powerprotect.protectionpolicy.Ppdm.login')
        self.mock_login = patcher_login.start()

    def test_with_token(self):
        test_policy = powerprotect.ProtectionPolicy(name="exists",
                                                    server="valid",
                                                    token="123abc")
        assert test_policy.name == "exists"
        assert test_policy.server == "valid"
        assert test_policy._token == "123abc"
        assert type(test_policy.headers) is dict

    def test_with_username_and_password(self):
        test_policy = powerprotect.ProtectionPolicy(name="exists",
                                                    server="valid",
                                                    password="123abc")
        assert test_policy._Ppdm__password == "123abc"
        assert test_policy.username == "admin"
