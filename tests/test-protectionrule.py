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
        print(test_rule.__dict__)
        self.assertDictEqual(test_rule.response, content_example['content'][0])
        self.assertEqual(test_rule.status_code, 200)
