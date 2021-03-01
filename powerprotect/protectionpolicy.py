from powerprotect.ppdm import Ppdm
from powerprotect import exceptions
from powerprotect import get_module_logger
from powerprotect import helpers

protectionpolicy_logger = get_module_logger(__name__)
protectionpolicy_logger.propagate = False


class ProtectionPolicy(Ppdm):

    def __init__(self, **kwargs):
        try:
            self.exists = False
            self.changed = False
            self.check_mode = kwargs.get('check_mode', False)
            self.msg = ""
            self.failure = False
            self.fail_msg = ""
            self.name = kwargs['name']
            self.body = {}
            self.target_body = {}
            self.url = ""
            super().__init__(**kwargs)
            if 'token' not in kwargs:
                super().login()
            self.get_policy()
        except KeyError as e:
            protectionpolicy_logger.error(f"Missing required field: {e}")
            raise exceptions.PpdmException(f"Missing required field: {e}")

    def get_policy(self):
        protection_rule = self.__get_protection_policy_by_name()
        if bool(protection_rule.response) is not False:
            self.exists = True
        self.body = protection_rule.response

    def delete_policy(self):
        if self.exists:
            if not self.check_mode:
                return_body = self.__delete_protection_rule(self.body['id'])
                self.exists = False
            if self.check_mode:
                protectionpolicy_logger.info("check mode enabled, "
                                             "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.body = {}
                self.msg = f"Protection rule {self.name} deleted"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.fail_msg

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
                self.get_rule()
            if self.check_mode:
                protectionpolicy_logger.info("check mode enabled, "
                                             "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.msg = f"Protection Rule {self.name} created"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.fail_msg
        elif self.exists:
            self.msg = f"Protection Rule {self.name} already exists"

    def update_rule(self):
        if (self.exists and
                helpers._body_match(self.body, self.target_body) is False):
            self.body.update(self.target_body)
            if not self.check_mode:
                return_body = self.__update_protection_rule(self.body)
                self.get_rule()
            if self.check_mode:
                protectionpolicy_logger.info("check mode enabled, "
                                             "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.target_body = {}
                self.msg = f"Protection Rule {self.name} updated"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.fail_msg

    def __create_protection_rule(self, policy_name, rule_name, inventory_type,
                                 label, **kwargs):
        protectionpolicy_logger.debug("Method: create_protection_rule")
        return_body = helpers.ReturnBody()
        inventory_types = ["KUBERNETES",
                           "VMWARE_VIRTUAL_MACHINE",
                           "FILE_SYSTEM",
                           "MICROSOFT_SQL_DATABASE",
                           "ORACLE_DATABASE"]
        if inventory_type not in inventory_types:
            err_msg = "Protection Rule not Created. Inventory Type not valid"
            protectionpolicy_logger.error(err_msg)
            return_body.success = False
            return_body.fail_msg = err_msg
        if return_body.success is None:
            protection_policy = (self.get_protection_policy_by_name(
                policy_name))
            if protection_policy.success is False:
                err_msg = f"Protection Policy not found: {policy_name}"
                protectionpolicy_logger.error(err_msg)
                return_body.success = False
                return_body.fail_msg = (err_msg)
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
            response = self._rest_post("/protection-rules", body)
            if response.ok is False:
                protectionpolicy_logger.error("Protection Rule not Created")
                return_body.success = False
                return_body.fail_msg = response.json()
                return_body.status_code = response.status_code
            elif response.ok is True:
                return_body.success = True
                return_body.response = response.json()
                return_body.status_code = response.status_code
        return return_body

    def __get_protection_policy_by_name(self):
        protectionpolicy_logger.debug("Method: get_protection_policy_by_name")
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
                protectionpolicy_logger.info(err_msg)
                return_body.success = True
                return_body.status_code = response.status_code
                return_body.response = {}
            else:
                return_body.success = True
                return_body.response = response.json()['content'][0]
                return_body.status_code = response.status_code
        return return_body

    def __update_protection_rule(self, body):
        protectionpolicy_logger.debug("Method: update_protection_rule")
        return_body = helpers.ReturnBody()
        protection_rule_id = body["id"]
        response = self._rest_put("/protection-rules"
                                  f"/{protection_rule_id}", body)
        if not response.ok:
            protectionpolicy_logger.error("Protection Rule not Updated")
            return_body.success = False
            return_body.fail_msg = response.json()
            return_body.status_code = response.status_code
        if return_body.success is None:
            return_body.success = True
            return_body.response = response.json()
            return_body.status_code = response.status_code
        return return_body

    def __delete_protection_rule(self, id):
        protectionpolicy_logger.debug("Method: delete_protection_rule")
        return_body = helpers.ReturnBody()
        response = self._rest_delete(f"/protection-rules/{id}")
        if not response.ok:
            protectionpolicy_logger.error(f"Protection Rule id \"{id}\" "
                                          "not deleted")
            return_body.success = False
            return_body.fail_msg = response.json()
        if return_body.success is None:
            return_body.success = True
            return_body.response = f"Protection Rule id \"{id}\" "\
                                    "successfully deleted"
        return_body.status_code = response.status_code
        return return_body
