import sys
from unittest import TestCase, mock
sys.path.insert(0, '../powerprotect/')
import powerprotect


class TestGetProtectionRulebyName(TestCase):
    def setUp(self):

        self.mock_protection_rule = mock.Mock(spec=powerprotect.ProtectionRule)
        self.mock_protection_rule.name = "test_rule"
        patcher_rest_get = mock.patch('powerprotect.protectionrule.'
                                      'Ppdm._rest_get')
        self.mock_rest_get = patcher_rest_get.start()
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.mock_protection_rule = None

    def test_get_protection_rule_by_name_exists(self):
        content_example = {'content': [{'key': 'value'}]}
        self.mock_rest_get.return_value.ok = True
        self.mock_rest_get.return_value.status_code = 200
        self.mock_rest_get.return_value.json.return_value = content_example
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__get_protection_rule_by_name(
                         self.mock_protection_rule))
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
                         self.mock_protection_rule))
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
                         self.mock_protection_rule))
        self.assertFalse(test_rule.success)
        self.assertDictEqual(test_rule.fail_msg, content_example)
        self.assertEqual(test_rule.status_code, 400)


class TestUpdateProtectionRule(TestCase):
    def setUp(self):
        self.mock_protection_rule = mock.Mock(spec=powerprotect.ProtectionRule)
        self.mock_protection_rule.name = "test_rule"
        self.mock_protection_rule.id = "0000-0000"
        self.mock_protection_rule.body = {'body': 'test'}
        patcher_rest_put = mock.patch('powerprotect.protectionrule.'
                                      'Ppdm._rest_put')
        self.mock_rest_put = patcher_rest_put.start()
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.mock_protection_rule = None

    def test_update_protection_rule_good(self):
        self.mock_rest_put.return_value.ok = True
        (self.mock_rest_put.
         return_value.json.return_value) = self.mock_protection_rule.body
        self.mock_rest_put.return_value.status_code = 200
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__update_protection_rule(
                         self.mock_protection_rule))
        print(self.mock_protection_rule.__dict__)
        self.assertTrue(test_rule.success)
        self.assertEqual(test_rule.status_code, 200)
        self.assertEqual(test_rule.response,
                         self.mock_protection_rule.body)

    def test_update_protection_rule_bad(self):
        self.mock_rest_put.return_value.ok = False
        self.mock_rest_put.return_value.json.return_value = self.mock_protection_rule.body
        self.mock_rest_put.return_value.status_code = 400
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__update_protection_rule(
                         self.mock_protection_rule))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 400)
        self.assertEqual(test_rule.fail_msg, self.mock_protection_rule.body)


class TestCreateProtectionRule(TestCase):
    def setUp(self):
        self.rule_dict_good = {'policy_name': 'test_policy',
                               'rule_name': 'test_rule',
                               'inventory_type': 'KUBERNETES',
                               'label': 'test=test'}
        patcher_rest_post = mock.patch('powerprotect.protectionrule.'
                                       'Ppdm._rest_post')
        self.mock_rest_post = patcher_rest_post.start()
        patcher_get_policy_by_name = mock.patch('powerprotect.protectionrule.'
                                                'Ppdm.get_protection_policy_by'
                                                '_name')
        self.mock_get_policy_by_name = patcher_get_policy_by_name.start()
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.mock_protection_rule = None

    def test_create_protection_rule_good(self):
        content_example = {'key': 'value'}
        self.mock_rest_post.return_value.ok = True
        self.mock_rest_post.return_value.json.return_value = content_example
        self.mock_rest_post.return_value.status_code = 200
        self.mock_get_policy_by_name.return_value.success = True
        self.mock_get_policy_by_name.return_value.response = {'id': 'policy_id'}
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__create_protection_rule(
                         powerprotect.ProtectionRule,
                         **self.rule_dict_good))
        self.assertTrue(test_rule.success)
        self.assertEqual(test_rule.status_code, 200)
        self.assertDictEqual(test_rule.response, content_example)

    def test_create_protection_rule_bad_policy(self):
        (self.mock_get_policy_by_name.return_value.success) = False
        (self.mock_get_policy_by_name.return_value.status_code) = 400
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__create_protection_rule(
                         powerprotect.ProtectionRule,
                         **self.rule_dict_good))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 400)
        self.assertEqual(test_rule.fail_msg,
                         "Protection Policy not found: "
                         f"{self.rule_dict_good['policy_name']}")

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
        self.mock_protection_rule = mock.Mock(spec=powerprotect.ProtectionRule)
        self.mock_protection_rule.name = "test_rule"
        self.mock_protection_rule.id = "0000-0000"
        patcher_rest_delete = mock.patch('powerprotect.protectionrule.'
                                         'Ppdm._rest_delete')
        self.mock_rest_delete = patcher_rest_delete.start()
        self.addCleanup(mock.patch.stopall)
                         
    def tearDown(self):
        self.mock_protection_rule = None

    def test_delete_protection_rule_good(self):
        self.mock_rest_delete.return_value.ok = True
        self.mock_rest_delete.return_value.status_code = 200
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__delete_protection_rule(
                         self.mock_protection_rule))
        self.assertTrue(test_rule.success)
        self.assertEqual(test_rule.status_code, 200)
        self.assertEqual(test_rule.response,
                         "Protection Rule id \"0000-0000\" "
                         "successfully deleted")

    def test_delete_protection_rule_bad(self):
        content_example = {'key': 'value'}
        self.mock_rest_delete.return_value.ok = False
        self.mock_rest_delete.return_value.json.return_value = content_example
        self.mock_rest_delete.return_value.status_code = 401
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__delete_protection_rule(
                         self.mock_protection_rule))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 401)
        self.assertDictEqual(test_rule.fail_msg, content_example)


class TestGetRule(TestCase):
    def setUp(self):
        self.mock_protection_rule = mock.Mock(spec=powerprotect.ProtectionRule)
        self.mock_protection_rule.name = "test_rule"
        self.mock_protection_rule.exists = False
        self.mock_protection_rule.body = {}

    def tearDown(self):
        self.mock_protection_rule = None

    def test_get_rule_not_exists(self):
        (self.mock_protection_rule.
         _ProtectionRule__get_protection_rule_by_name.
         return_value.response) = {}
        powerprotect.ProtectionRule.get_rule(self.mock_protection_rule)
        self.assertFalse(self.mock_protection_rule.exists)
        self.assertDictEqual(self.mock_protection_rule.body, {})

    def test_get_rule_exists(self):
        (self.mock_protection_rule.
         _ProtectionRule__get_protection_rule_by_name.
         return_value.response) = {'id': '0000-0000'}
        powerprotect.ProtectionRule.get_rule(self.mock_protection_rule)
        self.assertTrue(self.mock_protection_rule)
        self.assertEqual(self.mock_protection_rule.id, '0000-0000')
        self.assertDictEqual(self.mock_protection_rule.body,
                             {'id': '0000-0000'})