from powerprotect.ppdm import Ppdm
from powerprotect import exceptions
from powerprotect import get_module_logger
from powerprotect import helpers

protectionrule_logger = get_module_logger(__name__)
protectionrule_logger.propagate = False


class ProtectionRule(Ppdm):

    def __init__(self, **kwargs):
        try:
            self.exists = False
            self.changed = False
            self.check_mode = kwargs.get('check_mode', False)
            self.msg = ""
            self.failure = False
            self.fail_msg = ""
            self.fail_response = {}
            self.name = kwargs['name']
            self.body = {}
            self.target_body = {}
            self.url = ""
            self.id = ""
            super().__init__(**kwargs)
            if 'token' not in kwargs:
                super().login()
            self.get_rule()
        except KeyError as e:
            protectionrule_logger.error(f"Missing required field: {e}")
            raise exceptions.PpdmException(f"Missing required field: {e}")

    def get_rule(self):
        protection_rule = self.__get_protection_rule_by_name()
        if bool(protection_rule.response) is not False:
            self.exists = True
            self.id = protection_rule.response['id']
        else:
            self.exists = False
            self.id = ''
        self.body = protection_rule.response

    def delete_rule(self):
        if self.exists:
            if not self.check_mode:
                return_body = self.__delete_protection_rule()
            if self.check_mode:
                protectionrule_logger.info("check mode enabled, "
                                           "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.msg = f"Protection rule {self.name} deleted"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.msg
                self.fail_response = return_body.response
        self.get_rule()

    def create_rule(self, **kwargs):
        policy_name = kwargs['policy_name']
        inventory_type = kwargs['inventory_type']
        label = kwargs['label']
        if not self.exists:
            if not self.check_mode:
                return_body = self.__create_protection_rule(
                    rule_name=self.name,
                    policy_name=policy_name,
                    inventory_type=inventory_type,
                    label=label)
            if self.check_mode:
                protectionrule_logger.info("check mode enabled, "
                                           "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.msg = f"Protection Rule {self.name} created"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.msg
                self.fail_response = return_body.response
        elif self.exists:
            self.msg = f"Protection Rule {self.name} already exists"
        self.get_rule()

    def update_rule(self):
        if (self.exists and
                self.target_body and
                helpers._body_match(self.body, self.target_body) is False):
            if not self.check_mode:
                return_body = self.__update_protection_rule()
            if self.check_mode:
                protectionrule_logger.info("check mode enabled, "
                                           "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.msg = f"Protection Rule {self.name} updated"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.msg
                self.fail_response = return_body.response
        self.target_body = {}
        self.get_rule()

    def __create_protection_rule(self, policy_name, rule_name, inventory_type,
                                 label, **kwargs):
        protectionrule_logger.debug("Method: __create_protection_rule")
        return_body = helpers.ReturnBody()
        return_body.success = None
        inventory_types = ["KUBERNETES",
                           "VMWARE_VIRTUAL_MACHINE",
                           "FILE_SYSTEM",
                           "MICROSOFT_SQL_DATABASE",
                           "ORACLE_DATABASE"]
        if inventory_type not in inventory_types:
            msg = "Protection Rule not Created. Inventory Type not valid"
            return_body.success = False
        if return_body.success is None:
            protection_policy = (super().get_protection_policy_by_name(
                policy_name))
            if protection_policy.success is False:
                msg = f"Protection Policy not found: {policy_name}"
                return_body.success = False
                return_body.status_code = protection_policy.status_code
        if return_body.success is None:
            body = {'action': kwargs.get('action', 'MOVE_TO_GROUP'),
                    'name': rule_name,
                    'actionResult': (protection_policy.response['id']),
                    'conditions': [{
                        'assetAttributeName': 'userTags',
                        'operator': 'EQUALS',
                        'assetAttributeValue': label
                    }],
                    'connditionConnector': 'AND',
                    'inventorySourceType': inventory_type,
                    'priority': kwargs.get('priority', 1),
                    'tenant': {
                        'id': '00000000-0000-4000-a000-000000000000'
                    }
                    }
            response = super()._rest_post("/protection-rules", body)
            if response.ok:
                msg = f"Protection Rule id \"{self.name}\" " \
                    "successfully created"
                return_body.success = True
            else:
                msg = f"Protection Rule id \"{self.name}\" " \
                    "not created"
                return_body.success = False
            return_body.status_code = response.status_code
            return_body.response = response.json()
        return_body.msg = msg
        return return_body

    def __get_protection_rule_by_name(self):
        protectionrule_logger.debug("Method: get_protection_rule_by_name")
        return_body = helpers.ReturnBody()
        response = super()._rest_get("/protection-rules"
                                     f"?filter=name%20eq%20%22{self.name}%22")
        if response.ok is False:
            return_body.success = False
            return_body.fail_msg = response.json()
            return_body.status_code = response.status_code
        if response.ok:
            if not response.json()['content']:
                err_msg = f"Protection rule not found: {self.name}"
                protectionrule_logger.info(err_msg)
                return_body.success = True
                return_body.status_code = response.status_code
                return_body.response = {}
            else:
                return_body.success = True
                return_body.response = response.json()['content'][0]
                return_body.status_code = response.status_code
        return return_body

    def __update_protection_rule(self):
        protectionrule_logger.debug("Method: update_protection_rule")
        return_body = helpers.ReturnBody()
        future_body = self.body.copy()
        future_body.update(self.target_body)
        response = super()._rest_put("/protection-rules"
                                     f"/{self.id}", future_body)
        if response.ok:
            msg = f"Protection Rule id \"{self.name}\" successfully updated"
            return_body.success = True
        else:
            msg = f"Protection Rule id \"{self.name}\" not updated"
            return_body.success = False
        protectionrule_logger.debug(msg)
        return_body.msg = msg
        return_body.response = response.json()
        return_body.status_code = response.status_code
        return return_body

    def __delete_protection_rule(self):
        protectionrule_logger.debug("Method: __delete_protection_rule")
        return_body = helpers.ReturnBody()
        response = super()._rest_delete(f"/protection-rules/{self.id}")
        if response.ok:
            msg = f"Protection Rule id \"{self.name}\" successfully deleted"
            return_body.success = True
            return_body.response = {}
        else:
            msg = f"Protection Rule id \"{self.name}\" not deleted"
            return_body.success = False
            return_body.response = response.json()
        protectionrule_logger.debug(msg)
        return_body.msg = msg
        return_body.status_code = response.status_code
        return return_body
