import sys
from unittest import TestCase, mock
import pytest
sys.path.insert(0, '../powerprotect/')
import powerprotect


class TestProtectionRule(TestCase):
    @mock.patch('powerprotect.ppdm.Ppdm._rest_get')
    def test_get_protection_rule_by_name_exists(self, mock_rest_get):
        content_example = {'content': [{'key': 'value'}]}
        mock_rest_get.return_value.ok = True
        mock_rest_get.return_value.status_code = 200
        mock_rest_get.return_value.json.return_value = content_example
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__get_protection_rule_by_name(
                         powerprotect.ProtectionRule, "test"))
        self.assertTrue(test_rule.success)
        self.assertDictEqual(test_rule.response, content_example['content'][0])
        self.assertEqual(test_rule.status_code, 200)

    @mock.patch('powerprotect.ppdm.Ppdm._rest_get')
    def test_get_protection_rule_by_name_not_exists(self, mock_rest_get):
        content_example = {'content': []}
        mock_rest_get.return_value.ok = True
        mock_rest_get.return_value.status_code = 200
        mock_rest_get.return_value.json.return_value = content_example
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__get_protection_rule_by_name(
                         powerprotect.ProtectionRule, "test"))
        self.assertTrue(test_rule.success)
        self.assertFalse(test_rule.response)
        self.assertEqual(test_rule.status_code, 200)

    @mock.patch('powerprotect.ppdm.Ppdm._rest_get')
    def test_get_protection_rule_by_name_fail(self, mock_rest_get):
        content_example = {'key': 'value'}
        mock_rest_get.return_value.ok = False
        mock_rest_get.return_value.status_code = 400
        mock_rest_get.return_value.json.return_value = content_example
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__get_protection_rule_by_name(
                         powerprotect.ProtectionRule, "test"))
        self.assertFalse(test_rule.success)
        self.assertDictEqual(test_rule.fail_msg, content_example)
        self.assertEqual(test_rule.status_code, 400)

    @mock.patch('powerprotect.ppdm.Ppdm._rest_delete')
    def test_delete_protection_rule_good(self, mock_rest_delete):
        mock_rest_delete.return_value.ok = True
        mock_rest_delete.return_value.status_code = 200
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__delete_protection_rule(
                         powerprotect.ProtectionRule, "0000-1234"))
        self.assertTrue(test_rule.success)
        self.assertEqual(test_rule.status_code, 200)
        self.assertEqual(test_rule.response,
                         "Protection Rule id \"0000-1234\" "
                         "successfully deleted")

    @mock.patch('powerprotect.ppdm.Ppdm._rest_delete')
    def test_delete_protection_rule_bad(self, mock_rest_delete):
        content_example = {'key': 'value'}
        mock_rest_delete.return_value.ok = False
        mock_rest_delete.return_value.json.return_value = content_example
        mock_rest_delete.return_value.status_code = 401
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__delete_protection_rule(
                         powerprotect.ProtectionRule, "0000-1234"))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 401)
        self.assertDictEqual(test_rule.fail_msg, content_example)
