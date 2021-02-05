from powerprotect.ppdm import ReturnValue
from powerprotect import get_module_logger

protectionrule_logger = get_module_logger(__name__)
protectionrule_logger.propagate = False


class ProtectionRule:

    def __init__(self, **kwargs):
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
        self.ppdm = kwargs['ppdm']
        self.get_rule()

    def get_rule(self):
        protection_rule = self.ppdm.get_protection_rule_by_name(self.name)
        if bool(protection_rule.response) is not False:
            self.exists = True
            self.body = protection_rule.response

    def delete_rule(self):
        if self.exists:
            if not self.check_mode:
                return_value = self.ppdm.delete_protection_rule(self.body['id'])
                self.exists = False
            if self.check_mode:
                protectionrule_logger.info("check mode enabled, no action taken")
                return_value = ReturnValue()
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
                return_value = self.ppdm.create_protection_rule(rule_name=self.name,
                                                                policy_name=policy_name,
                                                                inventory_type=inventory_type,
                                                                label=label)
                self.get_rule()
            if self.check_mode:
                protectionrule_logger.info("check mode enabled, no action taken")
                return_value = ReturnValue()
                return_value.success = True
            if return_value.success:
                self.changed = True
                self.msg = f"Protection Rule {self.name} created"
            elif return_value.success is False:
                self.failure = True
                self.fail_msg = return_value.fail_msg

    def update_rule(self):
        if (self.exists and
            self.__body_match(self.body, self.target_body) is False):
            self.body.update(self.target_body)
            if not self.check_mode:
                return_value = self.ppdm.update_protection_rule(self.body)
                self.get_rule()
            if self.check_mode:
                protectionrule_logger.info("check mode enabled, no action taken")
                return_value = ReturnValue()
                return_value.success = True
            if return_value.success:
                self.changed = True
                self.target_body = {}
                self.msg = f"Protection Rule {self.name} updated"
            elif return_value.success is False:
                self.failure = True
                self.fail_msg = return_value.fail_msg

    def __body_match(self, server_dict, client_dict):
        combined_dict = {**server_dict, **client_dict}
        return server_dict == combined_dict
