from powerprotect.ppdm import Ppdm
from powerprotect.credential import Credential
from powerprotect import exceptions
from powerprotect import get_module_logger
from powerprotect import helpers

assetsource_logger = get_module_logger(__name__)
assetsource_logger.propagate = False
accpeted_types = ["DATADOMAINMANAGEMENTCENTER", "SMISPROVIDER", "DDSYSTEM",
                  "VMAXSYSTEM", "XTREMIOMANAGEMENTSERVER", "RECOVERPOINT",
                  "HOST_OS", "SQLGROUPS", "ORACLEGROUP", "DEFAULTAPPGROUP",
                  "VCENTER", "EXTERNALDATADOMAIN", "POWERPROTECTSYSTEM", "CDR",
                  "KUBERNETES", "PPDM", "UNITYMANAGEMENTSERVER",
                  "POWERSTOREMANAGEMENTSERVER"]


class AssetSource(Ppdm):
    def __init__(self, **kwargs):
        try:
            self.name = kwargs['name']
            self.id = ""
            self.type = ""
            self.body = {}
            self.target_body = {}
            self.exists = False
            self.changed = False
            self.check_mode = kwargs.get('check_mode', False)
            self.msg = ""
            self.failure = False
            self.fail_msg = ""
            self.fail_response = {}
            self.assests = {}
            super().__init__(**kwargs)
            if 'token' not in kwargs:
                super().login()
            self.get_assetsource()
        except KeyError as e:
            assetsource_logger.error(f"Missing required field: {e}")
            raise exceptions.PpdmException(f"Missing required field: {e}")

    def create_assetsource(self, **kwargs):
        address = kwargs['address']
        credential_name = kwargs['credential_name']
        tanzu = kwargs.get('tanzu', False)
        vcenter_name = kwargs.get('vcenter_name', '')
        port = kwargs['port']
        asset_type = (kwargs['asset_type']).upper()
        enable_vsphere_integration = kwargs.get('enable_vsphere_integration',
                                                False)
        if not self.exists:
            if not self.check_mode:
                return_body = self.__create_assetsource(
                    address=address,
                    credential_name=credential_name,
                    tanzu=tanzu,
                    vcenter_name=vcenter_name,
                    port=port,
                    asset_type=asset_type,
                    enable_vsphere_integration=enable_vsphere_integration)
            if self.check_mode:
                assetsource_logger.info("check mode enabled, "
                                        "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.msg = f"Assetsource {self.name} created"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.msg
                self.fail_response = return_body.response
        elif self.exists:
            self.msg = f"Assetsource {self.name} already exists"
        self.get_assetsource()

    def get_assetsource(self):
        assetsource = self.__get_assetsource_by_name()
        if bool(assetsource.response) is not False:
            self.exists = True
            self.id = assetsource.response['id']
            self.type = assetsource.response['type']
            self.assets = self.__get_all_assets()
        else:
            self.exists = False
            self.id = ""
        self.body = assetsource.response

    def update_assetsource(self):
        if (self.exists and
                self.target_body and
                helpers._body_match(self.body, self.target_body) is False):
            if not self.check_mode:
                return_body = self.__update_assetsource()
            if self.check_mode:
                assetsource_logger.info("check mode enabled, "
                                        "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.msg = f"Assetsource {self.name} updated"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.msg
                self.fail_response = return_body.response
        self.target_body = {}
        self.get_assetsource()

    def delete_assetsource(self):
        if self.exists:
            if not self.check_mode:
                return_body = self.__delete_assetsource()
            if self.check_mode:
                assetsource_logger.info("check mode enabled, "
                                        "no action taken")
                return_body = helpers.ReturnBody()
                return_body.success = True
            if return_body.success:
                self.changed = True
                self.msg = f"Assetsource {self.name} deleted"
            elif return_body.success is False:
                self.failure = True
                self.fail_msg = return_body.msg
                self.fail_response = return_body.response
        self.get_assetsource()

    def remove_all_assets_from_policies(self):
        assetsource_logger.debug("Method: remove_all_assets_from_policies")
        if self.exists:
            for asset in self.assets:
                if asset['protectionPolicyId']:
                    body = [asset['id']]
                    response = super()._rest_post("/protection-policies"
                                                  f"/{asset['protectionPolicyId']}"
                                                  "/asset-unassignments", body)
                    if response.ok is False:
                        assetsource_logger.error("Unable to remove asset:"
                                                 f"{asset['name']} from policy:"
                                                 f"{asset['protectionPolicy']['name']}")
                    if response.ok:
                        assetsource_logger.debug("Successfully removed asset:"
                                                 f"{asset['name']} from policy:"
                                                 f"{asset['protectionPolicy']['name']}")
            self.get_assetsource()

    def __get_all_assets(self):
        assetsource_logger.debug("Method: __get_all_assets")
        if self.type == "KUBERNETES":
            asset_source_type = "k8s"
        if self.type == "VCENTER":
            asset_source_type = "vm"
        response = super()._rest_get("/assets?filter=details."
                                     f"{asset_source_type}.inventorySourceId"
                                     f"%20eq%20%22{self.id}%22")
        if len(response.json()['content']) > 0:
            return response.json()['content']

    def __get_assetsource_by_name(self, **kwargs):
        assetsource_logger.debug("Method: __get_assetsource_by_name")
        return_body = helpers.ReturnBody()
        name = self.name
        if 'name' in kwargs:
            name = kwargs['name']
        response = super()._rest_get("/inventory-sources"
                                     f"?filter=name%20eq%20%22{name}%22")
        if response.ok is False:
            return_body.success = False
            return_body.fail_msg = response.json()
            return_body.status_code = response.status_code
        if response.ok:
            if not response.json()['content']:
                err_msg = f"Assetsource not found: {self.name}"
                assetsource_logger.info(err_msg)
                return_body.success = True
                return_body.status_code = response.status_code
                return_body.response = {}
            else:
                return_body.success = True
                return_body.response = response.json()['content'][0]
                return_body.status_code = response.status_code
        return return_body

    def __update_assetsource(self):
        assetsource_logger.debug("Method: __update_assetsource")
        return_body = helpers.ReturnBody()
        future_body = self.body.copy()
        future_body.update(self.target_body)
        response = super()._rest_put("/inventory-sources"
                                     f"/{self.id}", future_body)
        if response.ok:
            msg = f"Assetsource \"{self.name}\" successfully updated"
            return_body.success = True
        else:
            msg = f"Assetsource \"{self.name}\" not updated"
            return_body.success = False
        assetsource_logger.debug(msg)
        return_body.msg = msg
        return_body.response = response.json()
        return_body.status_code = response.status_code
        return return_body

    def __delete_assetsource(self):
        assetsource_logger.debug("Method: __delete_assetsource")
        return_body = helpers.ReturnBody()
        response = super()._rest_delete(f"/inventory-sources/{self.id}")
        if response.ok:
            msg = f"Assetsource \"{self.name}\" successfully deleted"
            certificate = self.__get_host_certificate(self.body['address'],
                                                      self.body['port'])
            self.__delete_host_certificate(certificate.response)
            return_body.success = True
            return_body.response = {}
        else:
            msg = f"Assetsource \"{self.name}\" not deleted"
            return_body.success = False
            return_body.response = response.json()
        assetsource_logger.debug(msg)
        return_body.msg = msg
        return_body.status_code = response.status_code
        return return_body

    def __create_assetsource(self, **kwargs):
        assetsource_logger.debug("Method: __create_assetsource")
        return_body = helpers.ReturnBody()
        certificate = self.__get_host_certificate(kwargs['address'],
                                                  kwargs['port'])
        self.__accept_host_certificate(certificate.response)
        credential = Credential(name=kwargs['credential_name'],
                                server=self.server,
                                token=self._token)
        body = {}
        body['address'] = kwargs['address']
        body['name'] = self.name
        body['port'] = kwargs['port']
        body['type'] = kwargs['asset_type']
        body.update({'credentials': {'id': credential.id}})
        if kwargs['asset_type'] == 'KUBERNETES' and kwargs['tanzu']:
            vcenter = self.__get_assetsource_by_name(name=kwargs
                                                     ['vcenter_name'])
            if vcenter.success:
                body.update({'details':
                             {'k8s':
                              {'vCenterId': vcenter.response['id']}}})
        if kwargs['asset_type'] == 'VCENTER':
            body.update({'details':
                         {'vCenter':
                          {'vSphereUiIntegration':
                           kwargs['enable_vsphere_integration']}}})
        response = super()._rest_post("/inventory-sources", body)
        if response.ok:
            msg = f"Assetsource id \"{self.name}\" " \
                   "successfully created"
            return_body.success = True
        else:
            msg = f"Assetsource id \"{self.name}\" " \
                   "not created"
            self.__delete_host_certificate(certificate.response)
            return_body.success = False
        return_body.status_code = response.status_code
        return_body.response = response.json()
        return_body.msg = msg
        return return_body

    def __get_host_certificate(self, address, port):
        assetsource_logger.debug("Method: __get_host_certificate")
        return_body = helpers.ReturnBody()
        response = super()._rest_get(f"/certificates?host={address}&port={port}"
                                     "&type=Host")
        if response.ok is False:
            return_body.success = False
            return_body.fail_msg = response.json()
            return_body.status_code = response.status_code
        if response.ok:
            return_body.success = True
            return_body.response = response.json()[0]
            return_body.status_code = response.status_code
        return return_body

    def __accept_host_certificate(self, cert):
        assetsource_logger.debug("Method: __accept_host_certificate")
        return_body = helpers.ReturnBody()
        cert['state'] = 'ACCEPTED'
        response = super()._rest_put(f"/certificates/{cert['id']}", cert)
        if response.ok:
            msg = f"Certificate \"{cert['host']}\" successfully accepted"
            return_body.success = True
        else:
            msg = f"Certificate \"{cert['host']}\" not accepted"
            return_body.success = False
        assetsource_logger.debug(msg)
        return_body.msg = msg
        return_body.response = response.json()
        return_body.status_code = response.status_code
        return return_body

    def __delete_host_certificate(self, cert):
        assetsource_logger.debug("Method: __delete_host_certificate")
        return_body = helpers.ReturnBody()
        response = super()._rest_delete(f"/certificates/{cert['id']}")
        if response.ok:
            msg = f"Certificate \"{cert['host']}\" successfully deleted"
            return_body.success = True
            return_body.response = {}
        else:
            msg = f"Certificate \"{cert['host']}\" not deleted"
            return_body.success = False
            return_body.response = response.json()
        assetsource_logger.debug(msg)
        return_body.msg = msg
        return_body.status_code = response.status_code
        return return_body
