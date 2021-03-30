from powerprotect.ppdm import Ppdm
from powerprotect import exceptions
from powerprotect import get_module_logger
from powerprotect import helpers

credential_logger = get_module_logger(__name__)
credential_logger.propagate = False


class Credential(Ppdm):

    def __init__(self, **kwargs):
        try:
            self.name = kwargs['name']
            self.id = ""
            self.body = {}
            self.target_body = {}
            self.exists = False
            self.changed = False
            self.check_mode = kwargs.get('check_mode', False)
            self.msg = ""
            self.failure = False
            self.fail_msg = ""
            self.fail_response = {}
            super().__init__(**kwargs)
            if 'token' not in kwargs:
                super().login()
            self.get_credential()
        except KeyError as e:
            credential_logger.error(f"Missing required field: {e}")
            raise exceptions.PpdmException(f"Missing required field: {e}")

    def create_credential(self, **kwargs):
        if not self.exists:
            if not self.check_mode:
                return_body = self.__create_credential(**kwargs)
            if self.check_mode:
                credential_logger.info("check mode enabled, "
                                       "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.msg = f"Credential {self.name} created"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.msg
                self.fail_response = return_body.response
        elif self.exists:
            self.msg = f"Credential {self.name} already exists"
        self.get_credential()

    def get_credential(self):
        credential = self.__get_credential_by_name()
        if bool(credential.response) is not False:
            self.exists = True
            self.id = credential.response['id']
        else:
            self.exists = False
            self.id = ""
        self.body = credential.response

    def update_credential(self):
        if (self.exists and
                self.target_body and
                helpers._body_match(self.body, self.target_body) is False):
            if not self.check_mode:
                return_body = self.__update_credential()
            if self.check_mode:
                credential_logger.info("check mode enabled, "
                                       "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.msg = f"Credential {self.name} updated"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.msg
                self.fail_response = return_body.response
        self.target_body = {}
        self.get_credential()

    def delete_credential(self):
        if self.exists:
            if not self.check_mode:
                return_body = self.__delete_credential()
            if self.check_mode:
                credential_logger.info("check mode enabled, "
                                       "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.msg = f"Credential {self.name} deleted"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.msg
                self.fail_response = return_body.response
        self.get_credential()

    def __get_credential_by_name(self):
        credential_logger.debug("Method: get_credential_by_name")
        return_body = helpers.ReturnBody()
        response = super()._rest_get("/credentials"
                                     f"?filter=name%20eq%20%22{self.name}%22")
        if response.ok is False:
            return_body.success = False
            return_body.fail_msg = response.json()
            return_body.status_code = response.status_code
        if response.ok:
            if not response.json()['content']:
                err_msg = f"Credential not found: {self.name}"
                credential_logger.info(err_msg)
                return_body.success = True
                return_body.status_code = response.status_code
                return_body.response = {}
            else:
                return_body.success = True
                return_body.response = response.json()['content'][0]
                return_body.status_code = response.status_code
        return return_body

    def __create_credential(self, **kwargs):
        credential_logger.debug("Method: __create_credential")
        return_body = helpers.ReturnBody()
        body = {'username': kwargs.get('username', self.name),
                'name': self.name,
                'password': kwargs['password']
                }
        if 'cred_type' in kwargs:
            body.update({'type': kwargs['cred_type']})
        if 'method' in kwargs:
            body.update({'method': kwargs['method']})
        response = super()._rest_post("/credentials", body)
        if response.ok:
            msg = f"Credential id \"{self.name}\" " \
                   "successfully created"
            return_body.success = True
        else:
            msg = f"Credential id \"{self.name}\" " \
                   "not created"
            return_body.success = False
        return_body.status_code = response.status_code
        return_body.response = response.json()
        return_body.msg = msg
        return return_body

    def __update_credential(self):
        credential_logger.debug("Method: __update_credential")
        return_body = helpers.ReturnBody()
        future_body = self.body.copy()
        future_body.update(self.target_body)
        response = super()._rest_put("/credentials"
                                     f"/{self.id}", future_body)
        if response.ok:
            msg = f"Credential \"{self.name}\" successfully updated"
            return_body.success = True
        else:
            msg = f"Credential \"{self.name}\" not updated"
            return_body.success = False
        credential_logger.debug(msg)
        return_body.msg = msg
        return_body.response = response.json()
        return_body.status_code = response.status_code
        return return_body

    def __delete_credential(self):
        credential_logger.debug("Method: __delete_credential")
        return_body = helpers.ReturnBody()
        response = super()._rest_delete(f"/credentials/{self.id}")
        if response.ok:
            msg = f"Credential \"{self.name}\" successfully deleted"
            return_body.success = True
            return_body.response = {}
        else:
            msg = f"Credential \"{self.name}\" not deleted"
            return_body.success = False
            return_body.response = response.json()
        credential_logger.debug(msg)
        return_body.msg = msg
        return_body.status_code = response.status_code
        return return_body
