import requests
import json
import urllib3
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


class Ppdm:

    def __init__(self, **kwargs):
        """Create a PPDM object that is authenticated"""
        self.server = kwargs['server']
        self.__password = kwargs.get('password', "")
        self.username = kwargs.get('username', "admin")
        self.headers = {'Content-Type': 'application/json'}
        self.__token = kwargs.get('token', "")
        if self.__token:
            self.headers.update({'Authorization': self.__token})

    def login(self):
        """Login method that extends the headers property to include the
        authorization key/value"""
        ppdm_logger.debug("Method: __login")
        body = {"username": self.username, "password": self.__password}
        response = self.__rest_post("/login", body)
        self.headers.update({'Authorization': json.loads(response.text
                                                         )['access_token']})

    def create_protection_rule(self, policy_name, rule_name, inventory_type,
                               label, **kwargs):
        protection_policy_id = (self.get_protection_policy_by_name(policy_name)
                                )["content"][0]["id"]
        ppdm_logger.debug("Method: create_protection_rule")
        body = {"action": kwargs.get('action', 'MOVE_TO_GROUP'),
                "name": rule_name,
                "actionResult": protection_policy_id,
                "conditions": [{
                    "assetAttributeName": "userTags",
                    "operator": "EQUALS",
                    "assetAttributeValue": label
                }],
                "connditionConnector": "AND",
                "inventorySourceType": inventory_type,
                "priority": kwargs.get('priority', 1),
                "tenant": {
                    "id": "00000000-0000-4000-a000-000000000000"
                }
                }
        response = self.__rest_post("/protection-rules", body)
        return json.loads(response.text)

    def get_protection_rules(self):
        ppdm_logger.debug("Method: get_protection_rules")
        response = self.__rest_get("/protection-rules")
        return json.loads(response.text)

    def get_protection_rule_by_name(self, name):
        ppdm_logger.debug("Method: get_protection_rule_by_name")
        response = self.__rest_get("/protection-rules"
                                   f"?filter=name%20eq%20%22{name}%22")
        return json.loads(response.text)["content"][0]

    def update_protection_rule(self, body):
        ppdm_logger.debug("Method: update_protection_rule")
        protection_rule_id = body["id"]
        response = self.__rest_put("/protection-rules"
                                   f"/{protection_rule_id}", body)
        return json.loads(response.text)

    def compare_protection_rule(self, existing_rule_name, expected_rule_body):
        ppdm_logger.debug("Method: compare_protection_rule")
        existing_rule = self.get_protection_rule_by_name(existing_rule_name)
        if self.__compare_body(existing_rule, expected_rule_body):
            return True

    def delete_protection_rule(self, id):
        ppdm_logger.debug("Method: delete_protection_rule")
        self.__rest_delete(f"/protection-rules/{id}")

    def get_protection_policies(self):
        ppdm_logger.debug("Method: get_protection_policies")
        response = self.__rest_get("/protection-policies")
        return json.loads(response.text)

    def get_protection_policy_by_name(self, name):
        ppdm_logger.debug("Method: get_protection_policy_by_name")
        response = self.__rest_get("/protection-policies"
                                   f"?filter=name%20eq%20%22{name}%22")
        return json.loads(response.text)

    def __rest_get(self, uri):
        ppdm_logger.debug("Method: __rest_get")
        response = requests.get(f"https://{self.server}:8443/api/v2"
                                f"{uri}",
                                verify=False,
                                headers=self.headers)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            ppdm_logger.error(f"Response Code: {response.status_code} "
                              f"Reason: {response.text} "
                              f"Error: {e}")
            return None
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
            ppdm_logger.error(f"Response Code: {response.status_code} "
                              f"Reason: {response.text} "
                              f"Error: {e}")
            return None
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
            ppdm_logger.error(f"Response Code: {response.status_code} "
                              f"Reason: {response.text} "
                              f"Error: {e}")
            return None
        return response

    def __compare_body(self, server_dict, client_dict):
        test = {**server_dict, **client_dict}
        if server_dict == test:
            return True

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
            ppdm_logger.error(f"Response Code: {response.status_code} "
                              f"Reason: {response.text} "
                              f"Error: {e}")
            return None
        return response
