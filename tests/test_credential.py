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
        self.mock_protection_rule.target_body = {'id': 'test'}
        self.mock_protection_rule.body = {'body': 'test'}
        self.future_body = (self.mock_protection_rule.
                            body.copy())
        self.future_body.update(self.mock_protection_rule.
                                target_body)
        patcher_rest_put = mock.patch('powerprotect.protectionrule.'
                                      'Ppdm._rest_put')
        self.mock_rest_put = patcher_rest_put.start()
        (self.mock_rest_put.return_value.json.
         return_value) = self.future_body
        self.mock_rest_put.return_value.status_code = 123

        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.mock_protection_rule = None

    def test_update_protection_rule_good(self):
        self.mock_rest_put.return_value.ok = True
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__update_protection_rule(
                         self.mock_protection_rule))
        self.assertTrue(test_rule.success)
        self.assertEqual(test_rule.status_code, 123)
        self.assertDictEqual(test_rule.response,
                             self.future_body)
        self.assertEqual(test_rule.msg,
                         "Protection Rule id "
                         f"\"{self.mock_protection_rule.name}\" "
                         "successfully updated")

    def test_update_protection_rule_bad(self):
        self.mock_rest_put.return_value.ok = False
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__update_protection_rule(
                         self.mock_protection_rule))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 123)
        self.assertDictEqual(test_rule.response,
                             self.future_body)
        self.assertEqual(test_rule.msg,
                         "Protection Rule id "
                         f"\"{self.mock_protection_rule.name}\" "
                         "not updated")


class TestCreateProtectionRule(TestCase):
    def setUp(self):
        self.mock_protection_rule = mock.Mock(spec=powerprotect.ProtectionRule)
        self.mock_protection_rule.name = 'test_rule'
        self.mock_protection_rule.id = "0000-0000"
        self.mock_protection_rule.body = {'body': 'test'}
        self.rule_dict_good = {'policy_name': 'test_policy',
                               'rule_name': 'test_rule',
                               'inventory_type': 'KUBERNETES',
                               'label': 'test=test'}
        self.rule_dict_bad = self.rule_dict_good.copy()
        self.rule_dict_bad.update({'inventory_type': 'bad_type'})
        patcher_rest_post = mock.patch('powerprotect.protectionrule.'
                                       'Ppdm._rest_post')
        self.mock_rest_post = patcher_rest_post.start()
        patcher_get_policy_by_name = mock.patch('powerprotect.protectionrule.'
                                                'Ppdm.get_protection_policy_by'
                                                '_name')
        self.mock_get_policy_by_name = patcher_get_policy_by_name.start()
        self.mock_rest_post.return_value.status_code = 123
        (self.mock_rest_post.return_value.
         json.return_value) = self.mock_protection_rule.body
        self.mock_get_policy_by_name.return_value.status_code = 123
        self.mock_get_policy_by_name.return_value.response = {'id': 'test'}
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.mock_protection_rule = None

    def test_create_protection_rule_good(self):
        self.mock_rest_post.return_value.ok = True
        self.mock_get_policy_by_name.return_value.success = True
        (self.mock_get_policy_by_name.return_value.
         response) = {'id': 'policy_id'}
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__create_protection_rule(
                         self.mock_protection_rule,
                         **self.rule_dict_good))
        self.assertTrue(test_rule.success)
        self.assertEqual(test_rule.status_code, 123)
        self.assertDictEqual(test_rule.response,
                             self.mock_protection_rule.body)
        self.assertEqual(test_rule.msg,
                         "Protection Rule id "
                         f"\"{self.mock_protection_rule.name}\" "
                         "successfully created")

    def test_create_protection_rule_bad_policy(self):
        (self.mock_get_policy_by_name.return_value.success) = False
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__create_protection_rule(
                         self.mock_protection_rule,
                         **self.rule_dict_good))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 123)
        self.assertDictEqual(test_rule.response, {})
        self.assertEqual(test_rule.msg,
                         "Protection Policy not found: "
                         f"{self.rule_dict_good['policy_name']}")

    def test_create_protection_rule_bad_inv_type(self):
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__create_protection_rule(
                         self.mock_protection_rule,
                         **self.rule_dict_bad))
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 0)
        self.assertDictEqual(test_rule.response, {})
        self.assertEqual(test_rule.msg,
                         "Protection Rule not Created. "
                         "Inventory Type not valid")

    def test_create_protection_rule_fails(self):
        self.mock_rest_post.return_value.ok = False
        self.mock_get_policy_by_name.return_value.success = True
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__create_protection_rule(
                         self.mock_protection_rule,
                         **self.rule_dict_good))
        self.assertFalse(test_rule.success)
        self.assertDictEqual(test_rule.response,
                             self.mock_protection_rule.body)
        self.assertEqual(test_rule.status_code, 123)
        self.assertEqual(test_rule.msg,
                         "Protection Rule id "
                         f"\"{self.mock_protection_rule.name}\" "
                         "not created")


class TestDeleteProtectionRule(TestCase):
    def setUp(self):
        self.mock_protection_rule = mock.Mock(spec=powerprotect.ProtectionRule)
        self.mock_protection_rule.name = "test_rule"
        self.mock_protection_rule.id = "0000-0000"
        patcher_rest_delete = mock.patch('powerprotect.protectionrule.'
                                         'Ppdm._rest_delete')
        self.mock_rest_delete = patcher_rest_delete.start()
        self.json_example = {'key': 'value'}
        (self.mock_rest_delete.return_value.
         json.return_value) = self.json_example
        self.mock_rest_delete.return_value.status_code = 123
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.mock_protection_rule = None

    def test_delete_protection_rule_good(self):
        self.mock_rest_delete.return_value.ok = True
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__delete_protection_rule(
                         self.mock_protection_rule))
        self.assertTrue(test_rule.success)
        self.assertEqual(test_rule.status_code, 123)
        self.assertDictEqual(test_rule.response, self.json_example)
        self.assertEqual(test_rule.msg,
                         "Protection Rule id "
                         f"\"{self.mock_protection_rule.name}\" "
                         "successfully deleted")

    def test_delete_protection_rule_bad(self):
        self.mock_rest_delete.return_value.ok = False
        test_rule = (powerprotect.ProtectionRule.
                     _ProtectionRule__delete_protection_rule(
                         self.mock_protection_rule))
        print(self.mock_rest_delete.__dict__)
        self.assertFalse(test_rule.success)
        self.assertEqual(test_rule.status_code, 123)
        self.assertDictEqual(test_rule.response, self.json_example)
        self.assertEqual(test_rule.msg,
                         "Protection Rule id "
                         f"\"{self.mock_protection_rule.name}\" "
                         "not deleted")


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


class TestUpdateRule(TestCase):
    def setUp(self):
        self.mock_protection_rule = mock.Mock(spec=powerprotect.ProtectionRule)
        self.mock_protection_rule.name = "test_rule"
        self.mock_protection_rule.exists = False
        self.mock_protection_rule.changed = False
        self.mock_protection_rule.body = {'orig': 'value'}
        self.mock_protection_rule.target_body = {}
        patcher_body_match = mock.patch('powerprotect.helpers._body_match')
        self.mock_body_match = patcher_body_match.start()
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.mock_protection_rule = None

    def test_update_rule_not_exists(self):
        powerprotect.ProtectionRule.update_rule(self.mock_protection_rule)
        self.assertDictEqual(self.mock_protection_rule.target_body, {})
        self.assertFalse(self.mock_protection_rule.changed)

    def test_update_rule_exists_no_diff(self):
        self.mock_protection_rule.exists = True
        self.mock_body_match.return_value = True
        powerprotect.ProtectionRule.update_rule(self.mock_protection_rule)
        self.assertDictEqual(self.mock_protection_rule.target_body, {})
        self.assertFalse(self.mock_protection_rule.changed)

    def test_update_rule_exists_no_target(self):
        self.mock_protection_rule.exists = True
        self.mock_body_match.return_value = True
        powerprotect.ProtectionRule.update_rule(self.mock_protection_rule)
        self.assertDictEqual(self.mock_protection_rule.target_body, {})
        self.assertFalse(self.mock_protection_rule.changed)

    def test_update_rule_exists_no_checkmode_success(self):
        (self.mock_protection_rule.
         _ProtectionRule__update_protection_rule.
         return_value.response) = {'id': '0000-0000'}
        (self.mock_protection_rule.
         _ProtectionRule__update_protection_rule.
         return_value.success) = True
        self.mock_body_match.return_value = False
        self.mock_protection_rule.check_mode = False
        self.mock_protection_rule.exists = True
        self.mock_protection_rule.target_body = {'new': 'things'}
        powerprotect.ProtectionRule.update_rule(self.mock_protection_rule)
        self.assertTrue(self.mock_protection_rule.changed)
        self.assertDictEqual(self.mock_protection_rule.target_body, {})

    def test_update_rule_exists_no_checkmode_failure(self):
        (self.mock_protection_rule.
         _ProtectionRule__update_protection_rule.
         return_value.response) = {'id': '0000-0000'}
        (self.mock_protection_rule.
         _ProtectionRule__update_protection_rule.
         return_value.success) = False
        (self.mock_protection_rule.
         _ProtectionRule__update_protection_rule.
         return_value.msg) = "updated the rule"
        self.mock_body_match.return_value = False
        self.mock_protection_rule.check_mode = False
        self.mock_protection_rule.exists = True
        self.mock_protection_rule.target_body = {'new': 'things'}
        powerprotect.ProtectionRule.update_rule(self.mock_protection_rule)
        self.assertFalse(self.mock_protection_rule.changed)
        self.assertTrue(self.mock_protection_rule.failure)
        self.assertEqual(self.mock_protection_rule.fail_msg,
                         "updated the rule")
        self.assertDictEqual(self.mock_protection_rule.target_body, {})

    def test_update_rule_exists_yes_checkmode(self):
        self.mock_body_match.return_value = False
        self.mock_protection_rule.check_mode = True
        self.mock_protection_rule.exists = True
        self.mock_protection_rule.target_body = {'new': 'things'}
        powerprotect.ProtectionRule.update_rule(self.mock_protection_rule)
        self.assertTrue(self.mock_protection_rule.changed)
        self.assertDictEqual(self.mock_protection_rule.target_body, {})


class TestDeleteRule(TestCase):
    def setUp(self):
        self.mock_protection_rule = mock.MagicMock(spec=powerprotect.
                                                   ProtectionRule)
        self.mock_protection_rule.name = "test_rule"
        self.mock_protection_rule.exists = False
        self.mock_protection_rule.changed = False
        self.mock_protection_rule.body = {}

    def tearDown(self):
        self.mock_protection_rule = None

    def test_delete_rule_not_exists(self):
        powerprotect.ProtectionRule.delete_rule(self.mock_protection_rule)
        self.assertFalse(self.mock_protection_rule.exists)
        self.assertFalse(self.mock_protection_rule.changed)

    def test_delete_rule_exists_no_checkmode(self):
        (self.mock_protection_rule.
         _ProtectionRule__delete_protection_rule.
         return_value.success) = True
        self.mock_protection_rule.check_mode = False
        self.mock_protection_rule.exists = True
        powerprotect.ProtectionRule.delete_rule(self.mock_protection_rule)
        self.assertEqual(self.mock_protection_rule.msg,
                         f"Protection rule {self.mock_protection_rule.name} "
                         "deleted")
        self.assertTrue(self.mock_protection_rule.changed)

    def test_delete_rule_exists_yes_checkmode(self):
        self.mock_protection_rule.check_mode = True
        self.mock_protection_rule.exists = True
        powerprotect.ProtectionRule.delete_rule(self.mock_protection_rule)
        self.assertEqual(self.mock_protection_rule.msg,
                         f"Protection rule {self.mock_protection_rule.name} "
                         "deleted")
        self.assertTrue(self.mock_protection_rule.changed)

    def test_delete_rule_exists_no_checkmode_fail(self):
        (self.mock_protection_rule.
         _ProtectionRule__delete_protection_rule.
         return_value.success) = False
        (self.mock_protection_rule.
         _ProtectionRule__delete_protection_rule.
         return_value.msg) = {"error": "id"}
        self.mock_protection_rule.check_mode = False
        self.mock_protection_rule.exists = True
        powerprotect.ProtectionRule.delete_rule(self.mock_protection_rule)
        self.assertEqual(self.mock_protection_rule.fail_msg, {"error": "id"})
        self.assertTrue(self.mock_protection_rule.failure)


class TestCreateRule(TestCase):
    def setUp(self):
        self.mock_protection_rule = mock.Mock(spec=powerprotect.ProtectionRule)
        self.mock_protection_rule.name = "test_rule"
        self.mock_protection_rule.exists = False
        self.mock_protection_rule.changed = False
        self.rule_dict_good = {'policy_name': 'test_policy',
                               'inventory_type': 'KUBERNETES',
                               'label': 'test=test'}
        self.rule_dict_bad = self.rule_dict_good.copy()
        self.rule_dict_bad.pop('inventory_type')
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.mock_protection_rule = None

    def test_create_rule_not_exists_no_checkmode_success(self):
        (self.mock_protection_rule.
         _ProtectionRule__create_protection_rule.
         return_value.success) = True
        self.mock_protection_rule.check_mode = False
        powerprotect.ProtectionRule.create_rule(self.mock_protection_rule,
                                                **self.rule_dict_good)
        self.assertEqual(self.mock_protection_rule.msg,
                         f"Protection Rule {self.mock_protection_rule.name} "
                         "created")
        self.assertTrue(self.mock_protection_rule.changed)

    def test_create_rule_not_exists_no_checkmode_failure(self):
        (self.mock_protection_rule.
         _ProtectionRule__create_protection_rule.
         return_value.success) = False
        (self.mock_protection_rule.
         _ProtectionRule__create_protection_rule.
         return_value.msg) = "message"
        self.mock_protection_rule.check_mode = False
        powerprotect.ProtectionRule.create_rule(self.mock_protection_rule,
                                                **self.rule_dict_good)
        self.assertEqual(self.mock_protection_rule.fail_msg, "message")
        self.assertFalse(self.mock_protection_rule.changed)
        self.assertTrue(self.mock_protection_rule.failure)

    def test_create_rule_not_exists_yes_checkmode(self):
        self.mock_protection_rule.check_mode = True
        powerprotect.ProtectionRule.create_rule(self.mock_protection_rule,
                                                **self.rule_dict_good)
        self.assertEqual(self.mock_protection_rule.msg,
                         f"Protection Rule {self.mock_protection_rule.name} "
                         "created")
        self.assertTrue(self.mock_protection_rule.changed)

    def test_create_rule_exists(self):
        self.mock_protection_rule.check_mode = False
        self.mock_protection_rule.exists = True
        powerprotect.ProtectionRule.create_rule(self.mock_protection_rule,
                                                **self.rule_dict_good)
        self.assertEqual(self.mock_protection_rule.msg,
                         f"Protection Rule {self.mock_protection_rule.name} "
                         "already exists")
        self.assertFalse(self.mock_protection_rule.changed)

    def test_create_rule_missing_kwargs(self):
        self.assertRaises(KeyError, powerprotect.ProtectionRule.create_rule,
                          self.mock_protection_rule,
                          **self.rule_dict_bad)


class TestInit(TestCase):
    def setUp(self):
        self.mock_protection_rule = mock.Mock(spec=powerprotect.AssetSource)
        self.rule_dict_token = {'name': 'test_rule',
                                'server': 'server',
                                'token': 'token'}
        self.rule_dict_bad = self.rule_dict_token.copy()
        self.rule_dict_bad.pop('name')
        self.rule_dict_password = self.rule_dict_token.copy()
        self.rule_dict_password.pop('token')
        self.rule_dict_password.update({'password': 'password'})
        patcher_get_policy = mock.patch(
            'powerprotect.protectionrule.ProtectionRule.get_rule')
        self.mock_get_policy = patcher_get_policy.start()
        patcher_login = mock.patch(
            'powerprotect.protectionrule.Ppdm.login')
        self.mock_login = patcher_login.start()
        self.addCleanup(mock.patch.stopall)

    def tearDown(self):
        self.mock_protection_policy = None

    def test_with_token(self):
        test_rule = powerprotect.ProtectionRule(**self.rule_dict_token)
        self.assertEqual(test_rule.name, "test_rule")
        self.assertEqual(test_rule.server, "server")
        self.assertEqual(test_rule._token, "token")
        self.assertFalse(test_rule.check_mode)
        self.assertEqual(type(test_rule.headers), dict)

    def test_init_missing_kwargs(self):
        self.assertRaises(powerprotect.PpdmException,
                          powerprotect.ProtectionRule,
                          **self.rule_dict_bad)

    def test_with_password(self):
        test_rule = powerprotect.ProtectionRule(**self.rule_dict_password)
        self.assertEqual(test_rule.name, "test_rule")
        self.assertEqual(test_rule.server, "server")
        self.assertEqual(test_rule._Ppdm__password, "password")
        self.assertFalse(test_rule.check_mode)
        self.assertEqual(type(test_rule.headers), dict)
