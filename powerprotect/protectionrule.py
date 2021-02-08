from powerprotect.ppdm import Ppdm
from powerprotect import exceptions
from powerprotect import get_module_logger
from powerprotect import helpers
from copy import deepcopy

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
            self.name = kwargs['name']
            self.body = {}
            self.target_body = {}
            self.url = ""
            Ppdm.__init__(self, **kwargs)
            self.get_rule()
        except KeyError as e:
            protectionrule_logger.error(f"Missing required field: {e}")
            raise exceptions.PpdmException(f"Missing required field: {e}")

    def get_rule(self):
        protection_rule = self.__get_protection_rule_by_name(self.name)
        if bool(protection_rule.response) is not False:
            self.exists = True
            self.body = protection_rule.response

    def delete_rule(self):
        if self.exists:
            if not self.check_mode:
                return_value = self.__delete_protection_rule(self.body['id'])
                self.exists = False
            if self.check_mode:
                protectionrule_logger.info("check mode enabled, "
                                           "no action taken")
                return_value = helpers.ReturnValue()
                return_value.success = True
            if return_value.success:
                self.changed = True
                self.body = {}
                self.msg = f"Protection rule {self.name} deleted"
            elif return_value.success is False:
                self.failure = True
                self.fail_msg = return_value.fail_msg

    def create_rule(self, **kwargs):
        policy_name = kwargs['policy_name']
        inventory_type = kwargs['inventory_type']
        label = kwargs['label']
        if not self.exists:
            if not self.check_mode:
                return_value = self.__create_protection_rule(
                    rule_name=self.name,
                    policy_name=policy_name,
                    inventory_type=inventory_type,
                    label=label)
                self.get_rule()
            if self.check_mode:
                protectionrule_logger.info("check mode enabled, "
                                           "no action taken")
                return_value = helpers.ReturnValue()
                return_value.success = True
            if return_value.success:
                self.changed = True
                self.msg = f"Protection Rule {self.name} created"
            elif return_value.success is False:
                self.failure = True
                self.fail_msg = return_value.fail_msg
        elif self.exists:
            self.msg = f"Protection Rule {self.name} already exists"

    def update_rule(self):
        if (self.exists and
                helpers._body_match(self.body, self.target_body) is False):
            self.body.update(self.target_body)
            if not self.check_mode:
                return_value = self.__update_protection_rule(self.body)
                self.get_rule()
            if self.check_mode:
                protectionrule_logger.info("check mode enabled, "
                                           "no action taken")
                return_value = helpers.ReturnValue()
                return_value.success = True
            if return_value.success:
                self.changed = True
                self.target_body = {}
                self.msg = f"Protection Rule {self.name} updated"
            elif return_value.success is False:
                self.failure = True
                self.fail_msg = return_value.fail_msg

    def __create_protection_rule(self, policy_name, rule_name, inventory_type,
                                 label, **kwargs):
        protectionrule_logger.debug("Method: create_protection_rule")
        return_value = helpers.ReturnValue()
        inventory_types = ["KUBERNETES",
                           "VMWARE_VIRTUAL_MACHINE",
                           "FILE_SYSTEM",
                           "MICROSOFT_SQL_DATABASE",
                           "ORACLE_DATABASE"]
        if inventory_type not in inventory_types:
            err_msg = "Protection Rule not Created. Inventory Type not valid"
            protectionrule_logger.error(err_msg)
            return_value.success = False
            return_value.fail_msg = err_msg
        if return_value.success is None:
            protection_policy = (self.get_protection_policy_by_name(
                policy_name))
            return_value = deepcopy(protection_policy)
            return_value.response = None
            return_value.response_code = None
        if return_value.success is True:
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
                protectionrule_logger.error("Protection Rule not Created")
                return_value.success = False
                return_value.fail_msg = response.json()
                return_value.status_code = response.status_code
            elif response.ok:
                return_value.success = True
                return_value.response = response.json()
                return_value.status_code = response.status_code
        return return_value

    def __get_protection_rules(self):
        protectionrule_logger.debug("Method: get_protection_rules")
        return_value = helpers.ReturnValue()
        response = self._rest_get("/protection-rules")
        if response.ok:
            return_value.response = response.json()
            return_value.success = True
        elif not response.ok:
            return_value.success = False
            return_value.fail_msg = 'API Failure'
            return_value.status_code = response.status_code
        return return_value

    def __get_protection_rule_by_name(self, name):
        protectionrule_logger.debug("Method: get_protection_rule_by_name")
        return_value = helpers.ReturnValue()
        response = self._rest_get("/protection-rules"
                                  f"?filter=name%20eq%20%22{name}%22")
        if response.ok is False:
            return_value.success = False
            return_value.fail_msg = response.json()
            return_value.status_code = response.status_code
        if response.ok:
            if not response.json()['content']:
                err_msg = f"Protection rule not found: {name}"
                protectionrule_logger.info(err_msg)
                return_value.success = True
                return_value.status_code = response.status_code
                return_value.response = {}
            else:
                return_value.success = True
                return_value.response = response.json()['content'][0]
                return_value.status_code = response.status_code
        return return_value

    def __update_protection_rule(self, body):
        protectionrule_logger.debug("Method: update_protection_rule")
        return_value = helpers.ReturnValue()
        protection_rule_id = body["id"]
        response = self._rest_put("/protection-rules"
                                  f"/{protection_rule_id}", body)
        if not response.ok:
            protectionrule_logger.error("Protection Rule not Updated")
            return_value.success = False
            return_value.fail_msg = response.json()
            return_value.status_code = response.status_code
        if return_value.success is None:
            return_value.success = True
            return_value.response = response.json()
            return_value.status_code = response.status_code
        return return_value

    def __delete_protection_rule(self, id):
        protectionrule_logger.debug("Method: delete_protection_rule")
        return_value = helpers.ReturnValue()
        response = self._rest_delete(f"/protection-rules/{id}")
        if not response.ok:
            protectionrule_logger.error(f"Protection Rule id \"{id}\" "
                                        "not deleted")
            return_value.success = False
            return_value.fail_msg = response.json()
        if return_value.success is None:
            return_value.success = True
            return_value.response = f"""Protection Rule id \"{id}\"
                                    successfully  deleted"""
        return_value.status_code = response.status_code
        return return_value
