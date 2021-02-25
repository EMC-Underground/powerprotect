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
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.mock_protection_policy = None

    def test_with_token(self):
        self.mock_login.return_value.ok = True
        self.mock_login.return_value.json.return_value = {'key': 'value'}
        test_policy = powerprotect.ProtectionPolicy(name="exists",
                                                    server="valid",
                                                    token="123abc")
        test = powerprotect.protectionpolicy.ProtectionPolicy.login()
        assert test_policy.name == "exists"
        assert test_policy.server == "valid"
        assert test_policy._token == "123abc"
        assert type(test_policy.headers) is dict
        assert test.ok is True
        assert type(powerprotect.protectionpolicy.ProtectionPolicy.login()
                    .json()) is dict

    def test_with_username_and_password(self):
        test_policy = powerprotect.ProtectionPolicy(name="exists",
                                                    server="valid",
                                                    password="123abc")
        assert test_policy._Ppdm__password == "123abc"
        assert test_policy.username == "admin"

    def test_with_no_name_info(self):
        with pytest.raises(Exception) as e_info:
            powerprotect.ProtectionPolicy(server="exists",
                                          password="123abc")
        assert e_info is not None


class TestGetPolicy(TestCase):

    def setUp(self):
        self.mock_protection_policy = mock.MagicMock(
            spec=powerprotect.ProtectionPolicy)
        self.mock_protection_policy.exists = False
        self.mock_protection_policy.body = {}
        self.mock_protection_policy.name = 'test'

    def test_policy_doesnt_exists(self):
        (self.mock_protection_policy.
         _ProtectionPolicy__get_protection_policy_by_name.
         return_value.response) = {}
        powerprotect.ProtectionPolicy.get_policy(self.mock_protection_policy)
        self.assertFalse(self.mock_protection_policy.exists)
        self.assertDictEqual(self.mock_protection_policy.body, {})

    def test_policy_exists(self):
        (self.mock_protection_policy.
         _ProtectionPolicy__get_protection_policy_by_name.
         return_value.response) = {'key': 'value'}
        powerprotect.ProtectionPolicy.get_policy(self.mock_protection_policy)
        self.assertTrue(self.mock_protection_policy.exists)
        self.assertDictEqual(self.mock_protection_policy.body,
                             {'key': 'value'})


class TestGetProtectionPolicyByName(TestCase):

    def setUp(self):
        self.mock_protection_policy = mock.MagicMock(
            spec=powerprotect.ProtectionPolicy)
        self.mock_protection_policy.name = 'test'
        patcher_rest_get = mock.patch(
            'powerprotect.protectionpolicy.Ppdm._rest_get')
        self.mock_rest_get = patcher_rest_get.start()
        self.addCleanup(mock.patch.stopall)

    def test_policy_exists(self):
        self.mock_rest_get.return_value.ok = True
        self.mock_rest_get.return_value.json.return_value = {'content':
                                                             [{'key': 'value'}
                                                              ]}
        self.mock_rest_get.return_value.status_code = 200
        test = (powerprotect.ProtectionPolicy.
                _ProtectionPolicy__get_protection_policy_by_name
                (self.mock_protection_policy))
        self.assertTrue(test.success)
        self.assertDictEqual(test.response, {'key': 'value'})
        self.assertEqual(test.status_code, 200)

    def test_policy_doesnt_exist(self):
        self.mock_rest_get.return_value.ok = True
        self.mock_rest_get.return_value.json.return_value = {'content': []}
        self.mock_rest_get.return_value.status_code = 200
        test = (powerprotect.ProtectionPolicy.
                _ProtectionPolicy__get_protection_policy_by_name
                (self.mock_protection_policy))
        self.assertTrue(test.success)
        self.assertDictEqual(test.response, {})
        self.assertEqual(test.status_code, 200)

    def test_response_is_fail(self):
        self.mock_rest_get.return_value.ok = False
        self.mock_rest_get.return_value.json.return_value = {}
        self.mock_rest_get.return_value.status_code = 401
        test = (powerprotect.ProtectionPolicy.
                _ProtectionPolicy__get_protection_policy_by_name
                (self.mock_protection_policy))
        self.assertFalse(test.success)
        self.assertDictEqual(test.fail_msg, {})
        self.assertEqual(test.status_code, 401)


class TestDeletePolicy(TestCase):

    def setUp(self):
        self.mock_protection_policy = mock.MagicMock(
            spec=powerprotect.ProtectionPolicy)
        self.mock_protection_policy.name = 'test'

    def tearDown(self):
        self.mock_protection_policy = None

    def test_policy_doesnt_exist(self):
        self.mock_protection_policy.exists = False
        powerprotect.ProtectionPolicy.delete_policy(
            self.mock_protection_policy)
        self.assertEqual(len(self.mock_protection_policy.method_calls), 0)
        self.assertFalse(self.mock_protection_policy.exists)

    def test_policy_exist_no_checkmode(self):
        self.mock_protection_policy.exists = True
        self.mock_protection_policy.check_mode = False
        powerprotect.ProtectionPolicy.delete_policy(
            self.mock_protection_policy)
        self.assertFalse(self.mock_protection_policy.exists)

    def test_policy_exist_yes_checkmode(self):
        self.mock_protection_policy.exists = True
        self.mock_protection_policy.check_mode = True
        powerprotect.ProtectionPolicy.delete_policy(
            self.mock_protection_policy)
        self.assertFalse(self.mock_protection_policy.exists)

    def test_policy_exists_success_is_false(self):
        self.mock_protection_policy.success = False
        powerprotect.ProtectionPolicy.delete_policy(
            self.mock_protection_policy)
