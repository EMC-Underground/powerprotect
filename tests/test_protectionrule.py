import sys
from unittest import TestCase, mock
sys.path.insert(0, '../powerprotect/')
import powerprotect


class TestGetProtectionRulebyName(TestCase):
    def setUp(self):
        patcher_rest_get = mock.patch('powerprotect.protectionrule.'
                                      'Ppdm._rest_get')
        self.mock_rest_get = patcher_rest_get.start()
        self.addCleanup(mock.patch.stopall)

    def test_get_protection_rule_by_name_exists(self):
        content_example = {'content': [{'key': 'value'}]}
        self.mock_rest_get.return_value.ok = True
        self.mock_rest_get.return_value.status_code = 200
        self.mock_rest_get.return_value.json.return_value = content_example
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__get_protection_rule_by_name(
                         powerprotect.ProtectionRule, "test"))
        self.assertTrue(test_rule.success)
        self.assertDictEqual(test_rule.response, content_example['content'][0])
        self.assertEqual(test_rule.status_code, 200)

    def test_get_protection_rule_by_name_not_exists(self):
        content_example = {'content': []}
        self.mock_rest_get.return_value.ok = True
        self.mock_rest_get.return_value.status_code = 200
        self.mock_rest_get.return_value.json.return_value = content_example
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__get_protection_rule_by_name(
                         powerprotect.ProtectionRule, "test"))
        self.assertTrue(test_rule.success)
        self.assertFalse(test_rule.response)
        self.assertEqual(test_rule.status_code, 200)

    def test_get_protection_rule_by_name_fail(self):
        content_example = {'key': 'value'}
        self.mock_rest_get.return_value.ok = False
        self.mock_rest_get.return_value.status_code = 400
        self.mock_rest_get.return_value.json.return_value = content_example
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__get_protection_rule_by_name(
                         powerprotect.ProtectionRule, "test"))
        self.assertFalse(test_rule.success)
        self.assertDictEqual(test_rule.fail_msg, content_example)
        self.assertEqual(test_rule.status_code, 400)


class TestUpdateProtectionRule(TestCase):
    def setUp(self):
        patcher_rest_put = mock.patch('powerprotect.protectionrule.'
                                      'Ppdm._rest_put')
        self.mock_rest_put = patcher_rest_put.start()
        self.addCleanup(mock.patch.stopall)

    def test_update_protection_rule_good(self):
        content_example = {'id': 'value'}
        self.mock_rest_put.return_value.ok = True
        self.mock_rest_put.return_value.json.return_value = content_example
        self.mock_rest_put.return_value.status_code = 200
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__update_protection_rule(
                         powerprotect.ProtectionRule,
                         content_example))
        self.assertTrue(test_rule.success)
        self.assertEqual(test_rule.status_code, 200)
        self.assertEqual(test_rule.response, content_example)

    def test_update_protection_rule_bad(self):
        content_example = {'id': 'value'}
        self.mock_rest_put.return_value.ok = False
        self.mock_rest_put.return_value.json.return_value = content_example
        self.mock_rest_put.return_value.status_code = 400
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__update_protection_rule(
                         powerprotect.ProtectionRule,
                         content_example))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 400)
        self.assertEqual(test_rule.fail_msg, content_example)


class TestCreateProtectionRule(TestCase):
    def setUp(self):
        patcher_rest_post = mock.patch('powerprotect.protectionrule.'
                                       'Ppdm._rest_post')
        self.mock_rest_post = patcher_rest_post.start()
        patcher_get_policy_by_name = mock.patch('powerprotect.protectionrule.'
                                                'Ppdm.'
                                                'get_protection_policy'
                                                '_by_name')
        self.mock_get_policy_by_name = patcher_get_policy_by_name.start()
        self.addCleanup(mock.patch.stopall)
        self.rule_dict_good = {'policy_name': 'valid_policy',
                               'rule_name': 'test_rule',
                               'inventory_type': 'KUBERNETES',
                               'label': 'valid_label'}
        self.rule_dict_bad = self.rule_dict_good.copy()
        self.rule_dict_bad.update('

    def test_create_protection_rule_good(self):
        content_example = {'key': 'value'}
        self.mock_rest_post.return_value.ok = True
        self.mock_rest_post.return_value.json.return_value = content_example
        self.mock_rest_post.return_value.status_code = 200
        self.mock_get_policy_by_name.return_value.success = True
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__create_protection_rule(
                         powerprotect.ProtectionRule,
                         **self.rule_dict_good))
        self.assertTrue(test_rule.success)
        self.assertEqual(test_rule.status_code, 200)
        self.assertDictEqual(test_rule.response, content_example)

    def test_create_protection_rule_bad_policy(self):
        self.mock_get_policy_by_name.return_value.success = False
        self.mock_get_policy_by_name.return_value.status_code = 400
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__create_protection_rule(
                         powerprotect.ProtectionRule,
                         **self.rule_dict_good))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 400)
        self.assertEqual(test_rule.fail_msg,
                         "Protection Policy not found: "
                         f"{rule_dict['policy_name']}")

    def test_create_protection_rule_bad_inv_type(self):
        rule_dict = {'policy_name': 'invalid_policy',
                     'rule_name': 'test_rule',
                     'inventory_type': 'bad_type',
                     'label': 'valid_label'}
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__create_protection_rule(
                         powerprotect.ProtectionRule,
                         **rule_dict))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, None)
        self.assertEqual(test_rule.fail_msg,
                         "Protection Rule not Created. "
                         "Inventory Type not valid")

    def test_create_protection_rule_fails(self):
        content_example = {'key': 'value'}
        rule_dict = {'policy_name': 'invalid_policy',
                     'rule_name': 'test_rule',
                     'inventory_type': 'KUBERNETES',
                     'label': 'valid_label'}
        self.mock_rest_post.return_value.ok = False
        self.mock_rest_post.return_value.json.return_value = content_example
        self.mock_rest_post.return_value.status_code = 400
        self.mock_get_policy_by_name.return_value.success = True
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__create_protection_rule(
                         powerprotect.ProtectionRule,
                         **rule_dict))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 400)
        self.assertEqual(test_rule.fail_msg, content_example)


class TestDeleteProtectionRule(TestCase):
    def setUp(self):
        patcher_rest_delete = mock.patch('powerprotect.protectionrule.'
                                         'Ppdm._rest_delete')
        self.mock_rest_delete = patcher_rest_delete.start()
        self.addCleanup(mock.patch.stopall)

    def test_delete_protection_rule_good(self):
        self.mock_rest_delete.return_value.ok = True
        self.mock_rest_delete.return_value.status_code = 200
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__delete_protection_rule(
                         powerprotect.ProtectionRule, "0000-1234"))
        self.assertTrue(test_rule.success)
        self.assertEqual(test_rule.status_code, 200)
        self.assertEqual(test_rule.response,
                         "Protection Rule id \"0000-1234\" "
                         "successfully deleted")

    def test_delete_protection_rule_bad(self):
        content_example = {'key': 'value'}
        self.mock_rest_delete.return_value.ok = False
        self.mock_rest_delete.return_value.json.return_value = content_example
        self.mock_rest_delete.return_value.status_code = 401
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__delete_protection_rule(
                         powerprotect.ProtectionRule, "0000-1234"))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 401)
        self.assertDictEqual(test_rule.fail_msg, content_example)


class TestGetRule(TestCase):
    def setUp(self):
        patcher_get_rule_by_name = mock.patch('powerprotect.protectionrule.'
                                              'ProtectionRule._ProtectionRule'
                                              '__get_protection_rule_by_name')
        self.mock_get_rule_by_name = patcher_get_rule_by_name.start()
        patcher_test_protection_rule = mock.patch('powerprotect.'
                                                  'protectionrule.'
                                                  'ProtectionRule')
        self.mock_test_protection_rule = patcher_test_protection_rule.start()

    def test_get_rule_exists(self):

