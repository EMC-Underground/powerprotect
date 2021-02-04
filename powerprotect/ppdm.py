import requests
import json
import urllib3
from copy import deepcopy
from powerprotect import get_module_logger

urllib3.disable_warnings()

ppdm_logger = get_module_logger(__name__)
ppdm_logger.propagate = False


"""
This module handles Dell Powerprotect. Current scope is to handle
authentication, protection rules and protection policy CRUD

# TODO

 - Add protection policy CRUD

"""


class ReturnValue:

    def __init__(self):
        self.success = None
        self.fail_msg = None
        self.status_code = None
        self.response = None


class PpdmException(Exception):
    pass


class Ppdm:

    def __init__(self, **kwargs):
        """Create a PPDM object that is authenticated"""
        try:
            self.server = kwargs['server']
            self.__password = kwargs.get('password', "")
            self.username = kwargs.get('username', "admin")
            self.headers = {'Content-Type': 'application/json'}
            self.__token = kwargs.get('token', "")
            if self.__token:
                self.headers.update({'Authorization': self.__token})
        except KeyError as e:
            ppdm_logger.error(f"Missing required field: {e}")
            raise PpdmException(f"Missing required field: {e}")

    def login(self):
        """Login method that extends the headers property to include the
        authorization key/value"""
        ppdm_logger.debug("Method: __login")
        body = {"username": self.username, "password": self.__password}
        response = self.__rest_post("/login", body)
        self.headers.update({'Authorization': response.json()['access_token']})

    def create_protection_rule(self, policy_name, rule_name, inventory_type,
                               label, **kwargs):
        ppdm_logger.debug("Method: create_protection_rule")
        return_value = ReturnValue()
        inventory_types = ["KUBERNETES",
                           "VMWARE_VIRTUAL_MACHINE",
                           "FILE_SYSTEM",
                           "MICROSOFT_SQL_DATABASE",
                           "ORACLE_DATABASE"]
        if inventory_type not in inventory_types:
            err_msg = "Protection Rule not Created. Inventory Type not valid"
            ppdm_logger.error(err_msg)
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
            response = self.__rest_post("/protection-rules", body)
            if response.ok is False:
                ppdm_logger.error("Protection Rule not Created")
                return_value.success = False
                return_value.fail_msg = response.json()
                return_value.status_code = response.status_code
            elif response.ok:
                return_value.success = True
                return_value.response = response.json()
                return_value.status_code = response.status_code
        return return_value

    def get_protection_rules(self):
        ppdm_logger.debug("Method: get_protection_rules")
        return_value = ReturnValue()
        response = self.__rest_get("/protection-rules")
        if response.ok:
            return_value.response = response.json()
            return_value.success = True
        elif not response.ok:
            return_value.success = False
            return_value.fail_msg = 'API Failure'
            return_value.status_code = response.status_code
        return return_value

    def get_protection_rule_by_name(self, name):
        ppdm_logger.debug("Method: get_protection_rule_by_name")
        return_value = ReturnValue()
        response = self.__rest_get("/protection-rules"
                                   f"?filter=name%20eq%20%22{name}%22")
        if not response.ok:
            return_value.success = False
            return_value.fail_msg = response.json()
            return_value.status_code = response.status_code
        if (not response.json()['content'] and
            return_value.success is not False):
            err_msg = f"Protection rule not found: {name}"
            ppdm_logger.info(err_msg)
            return_value.success = True
            return_value.status_code = response.status_code
            return_value.response = {}
        if return_value.success is None:
            return_value.success = True
            return_value.response = response.json()['content'][0]
            return_value.status_code = response.status_code
        return return_value

    def update_protection_rule(self, body):
        ppdm_logger.debug("Method: update_protection_rule")
        return_value = ReturnValue()
        protection_rule_id = body["id"]
        response = self.__rest_put("/protection-rules"
                                   f"/{protection_rule_id}", body)
        if not response.ok:
            ppdm_logger.error("Protection Rule not Updated")
            return_value.success = False
            return_value.fail_msg = response.json()
            return_value.status_code = response.status_code
        if return_value.success is None:
            return_value.success = True
            return_value.response = response.json()
            return_value.status_code = response.status_code
        return return_value

    def protection_rules_match(self, existing_rule_body, expected_rule_body):
        ppdm_logger.debug("Method: compare_protection_rule")
        return self.__compare_body(existing_rule_body, expected_rule_body)

    def delete_protection_rule(self, id):
        ppdm_logger.debug("Method: delete_protection_rule")
        return_value = ReturnValue()
        response = self.__rest_delete(f"/protection-rules/{id}")
        if not response.ok:
            ppdm_logger.error(f"Protection Rule id \"{id}\" not deleted")
            return_value.success = False
            return_value.fail_msg = response.json()
        if return_value.success is None:
            return_value.success = True
            return_value.response = f"""Protection Rule id \"{id}\"
                                    successfully  deleted"""
        return_value.status_code = response.status_code
        return return_value

    def get_protection_policies(self):
        ppdm_logger.debug("Method: get_protection_policies")
        response = self.__rest_get("/protection-policies")
        return response.json()['content']

    def get_protection_policy_by_name(self, name):
        ppdm_logger.debug("Method: get_protection_policy_by_name")
        return_value = ReturnValue()
        response = self.__rest_get("/protection-policies"
                                   f"?filter=name%20eq%20%22{name}%22")
        if not response.ok:
            return_value.success = False
            return_value.fail_msg = response.json()
            return_value.status_code = response.status_code
        if (not response.json()['content'] and
            return_value.success is not False):
            err_msg = f"protection policy not found: {name}"
            ppdm_logger.info(err_msg)
            return_value.success = True
            return_value.status_code = response.status_code
            return_value.response = {}
        if return_value.success is None:
            return_value.success = True
            return_value.response = response.json()['content'][0]
            return_value.status_code = response.status_code
        return return_value

    def __rest_get(self, uri):
        ppdm_logger.debug("Method: __rest_get")
        response = requests.get(f"https://{self.server}:8443/api/v2"
                                f"{uri}",
                                verify=False,
                                headers=self.headers)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            ppdm_logger.error(f"Reason: {response.text}")
            ppdm_logger.error(f"Error: {e}")
        ppdm_logger.debug(f"URL: https://{self.server}:8443/api/v2{uri}")
        ppdm_logger.debug(f"API Response OK?: {response.ok}")
        ppdm_logger.debug(f"API Status Code: {response.status_code}")
        return response

    def __rest_delete(self, uri):
        ppdm_logger.debug("Method: __rest_delete")
        response = requests.delete(f"https://{self.server}:8443/api/v2"
                                   f"{uri}",
                                   verify=False,
                                   headers=self.headers)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            ppdm_logger.error(f"Reason: {response.text}")
            ppdm_logger.error(f"Error: {e}")
        ppdm_logger.debug(f"URL: https://{self.server}:8443/api/v2{uri}")
        ppdm_logger.debug(f"API Response OK?: {response.ok}")
        ppdm_logger.debug(f"API Status Code: {response.status_code}")
        return response

    def __rest_post(self, uri, body):
        ppdm_logger.debug("Method: __rest_post")
        response = requests.post(f"https://{self.server}:8443/api/v2"
                                 f"{uri}",
                                 verify=False,
                                 data=json.dumps(body),
                                 headers=self.headers)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            ppdm_logger.error(f"Reason: {response.text}")
            ppdm_logger.error(f"Error: {e}")
        ppdm_logger.debug(f"URL: https://{self.server}:8443/api/v2{uri}")
        ppdm_logger.debug(f"API Response OK?: {response.ok}")
        ppdm_logger.debug(f"API Status Code: {response.status_code}")
        return response

    def __compare_body(self, server_dict, client_dict):
        test = {**server_dict, **client_dict}
        return server_dict == test

    def __rest_put(self, uri, body):
        ppdm_logger.debug("Method: __rest_put")
        response = requests.put(f"https://{self.server}:8443/api/v2"
                                f"{uri}",
                                verify=False,
                                data=json.dumps(body),
                                headers=self.headers)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            ppdm_logger.error(f"Reason: {response.text}")
            ppdm_logger.error(f"Error: {e}")
        ppdm_logger.debug(f"URL: https://{self.server}:8443/api/v2{uri}")
        ppdm_logger.debug(f"API Response OK?: {response.ok}")
        ppdm_logger.debug(f"API Status Code: {response.status_code}")
        return response
