import requests
import json
import urllib3
from powerprotect import get_module_logger
from powerprotect import helpers
from powerprotect import exceptions

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
        try:
            self.server = kwargs['server']
            self.__password = kwargs.get('password', "")
            self.username = kwargs.get('username', "admin")
            self.headers = {'Content-Type': 'application/json'}
            self._token = kwargs.get('token', "")
            if self._token:
                self.headers.update({'Authorization': self._token})
        except KeyError as e:
            ppdm_logger.error(f"Missing required field: {e}")
            raise exceptions.PpdmException(f"Missing required field: {e}")

    def login(self):
        """Login method that extends the headers property to include the
        authorization key/value"""
        ppdm_logger.debug("Method: __login")
        return_body = helpers.ReturnBody()
        body = {"username": self.username, "password": self.__password}
        response = self._rest_post("/login", body)
        if response.ok is False:
            ppdm_logger.error("Authentication Error")
            return_body.success = False
            return_body.fail_msg = response.json()
            return_body.status_code = response.status_code
        elif response.ok:
            return_body.success = True
            return_body.response = response.json()
            return_body.status_code = response.status_code
            self._token = response.json()['access_token']
            self.headers.update(
                {'Authorization': response.json()['access_token']})
        return return_body

    def get_protection_policies(self):
        ppdm_logger.debug("Method: get_protection_policies")
        response = self._rest_get("/protection-policies")
        return response.json()['content']

    def get_protection_policy_by_name(self, name):
        ppdm_logger.debug("Method: get_protection_policy_by_name")
        return_body = helpers.ReturnBody()
        response = self._rest_get("/protection-policies"
                                  f"?filter=name%20eq%20%22{name}%22")
        if not response.ok:
            msg = f"Protection Policy \"{name}\" not found"
            return_body.success = False
            return_body.response = response.json()
        else:
            if response.json()['content']:
                msg = f"Protection Policy \"{name}\" found"
                return_body.success = True
                return_body.response = response.json()['content'][0]
            else:
                msg = f"Protection Policy \"{name}\" not found"
                return_body.success = True
                return_body.response = {}
        return_body.msg = msg
        return_body.status_code = response.status_code
        return return_body

    def __get_protection_rules(self):
        ppdm_logger.debug("Method: __get_protection_rules")
        return_body = helpers.ReturnBody()
        response = self._rest_get("/protection-rules")
        if response.ok:
            return_body.response = response.json()
            return_body.success = True
        elif not response.ok:
            return_body.success = False
            return_body.fail_msg = 'API Failure'
            return_body.status_code = response.status_code
        return return_body

    def _rest_get(self, uri):
        ppdm_logger.debug("Method: _rest_get")
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

    def _rest_delete(self, uri):
        ppdm_logger.debug("Method: _rest_delete")
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

    def _rest_post(self, uri, body):
        ppdm_logger.debug("Method: _rest_post")
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

    def _rest_put(self, uri, body):
        ppdm_logger.debug("Method: _rest_put")
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
