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
