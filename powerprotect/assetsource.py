import paramiko
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
    """ Class to define an Asset Source object

    Asset source object creation require: name, server, password
    At object creation this library will go gather any information about
    this object, if it exists on the PPDM server.

    There are five interactive methods intended for user interaction:
        create_assetsource
        get_assetsource (run after creation and after all modification
                         operations automatically)
        update_assetsource
        delete_assetsource
        remove_all_assets_from_policies

    Attributes:
        name (str): Display name of the asset source (unique)
        id (str): Unique ID of the asset source (unique)
        type (str): Asset source type, only from list of acepted types
        body (dict): Return payload from PPDM server.
        target_body (dict): Body to be used for updates to the object
        exists (bool): Used to detirmine if the object exists on the PPDM
                       server
        check_mode (bool): If true pretend to modify object on the PPDM server
        msg (str): Return message of previous operations
        failure (bool): If true, the previous operation failed
        fail_msg (str): Detailed message from previous failure
        fail_response (dict): Payload returned from PPDM after a failure
        assets (list): List of all assets that are part of this asset source
    """
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
            self.discovery = {}
            self.msg = ""
            self.failure = False
            self.fail_msg = ""
            self.fail_response = {}
            self.assets = []
            super().__init__(**kwargs)
            if 'token' not in kwargs:
                super().login()
            self.get_assetsource()
        except KeyError as e:
            assetsource_logger.error(f"Missing required field: {e}")
            raise exceptions.PpdmException(f"Missing required field: {e}")

    def create_assetsource(self, credential_id=None, credential_name=None,
                           **kwargs):
        """ Method to create asset source if not present

        This method will create an asset source if not already present. After
        this method runs the get_assetsource method will execute updating the
        objects attributes.

        Check_Mode: True

        Args:
            address (str): FQDN or IP of asset source
            port (int): Port to communicate with asset source
            asset_type (str): PPDM Asset Source Type
            credential_name (str): Unique name of cred to use for auth
            tanzu (bool, default: False): For k8s tanzu clusters specify True
            vcenter_name (str): If Tanzu k8s, specify unique vcenter name. This
                                must already be an asset source in PPDM
            enable_vsphere_integration (bool): For vcenter asset source type,
                                               set to True in order to enable.

        Returns:
            None
        """
        try:
            address = kwargs['address']
            port = kwargs['port']
            asset_type = (kwargs['asset_type']).upper()
        except KeyError as e:
            raise exceptions.PpdmException(f"Missing required argument: {e}")
        tanzu = kwargs.get('tanzu', False)
        vcenter_name = kwargs.get('vcenter_name', '')
        vcenter_id = kwargs.get('vcenter_id', '')
        enable_vsphere_integration = kwargs.get('enable_vsphere_integration',
                                                False)
        if not self.exists:
            if not self.check_mode:
                return_body = self.__create_assetsource(
                    address=address,
                    credential_name=credential_name,
                    credential_id=credential_id,
                    tanzu=tanzu,
                    vcenter_name=vcenter_name,
                    vcenter_id=vcenter_id,
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
        """ Method to gather asset source information if present

        This method can be thought of as a sync between PPDM and an asset
        source object. As such it is run at object creation time, and after
        each of the other four methods. This method updates attributes only

        Args:
            None

        Returns:
            None
        """
        assetsource = self.__get_assetsource_by_name()
        if bool(assetsource.response) is not False:
            self.exists = True
            self.id = assetsource.response['id']
            self.type = assetsource.response['type']
            self.assets = self.__get_all_assets()
            self.__get_asset_source_discovery()
        else:
            self.exists = False
            self.id = ""
            self.assets = []
            self.discovery = {}
        self.body = assetsource.response

    def update_assetsource(self):
        """ Method to update asset source if present

        This method uses the target_body attribute to update the asset source
        in PPDM. If there is no asset sourcein PPDM  or target_body
        attribute, nothing will happen. After this method completes, the
        get_assetsource method will run and the target_body attribute will
        clear itself.

        Check_Mode: True

        Args:
            None

        Returns:
            None
        """
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
        """ Method to destroy asset source if present

        This method will delete the asset source from PPDM. If the asset source
        does not exist nothing will happen. After this method completes the
        get_assetsource method will run to update this objects attributes.

        Check_Mode: True

        Args:
            None

        Returns:
            None
        """
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
        """ Method to remove an asset sources assets from any protection
            policies

        This method finds any assets from the objects asset source that belong
        to a protection policy. Typically used before removing an asset
        source. After this method completes the get_assetsource method will
        run to update the objects attributes.

        Check_Mode: False

        Args:
            None

        Returns:
            None
        """
        assetsource_logger.debug("Method: remove_all_assets_from_policies")
        if self.exists:
            for asset in self.assets:
                if asset['protectionPolicyId']:
                    body = [asset['id']]
                    response = super()._rest_post(f"""/protection-policies
                                                  /{asset['protection'
                                                  'PolicyId']}
                                                  /asset-unassignments""",
                                                  body)
                    if response.ok is False:
                        assetsource_logger.error(f"""Unable to remove asset:
                                                 {asset['name']} from policy:
                                                 {asset['protectionPolicy']
                                                 ['name']}""")
                    if response.ok:
                        assetsource_logger.debug(f"""Successfully removed
                                                 asset: {asset['name']} from
                                                 policy: {asset['protection'
                                                 'Policy']['name']}""")
            self.get_assetsource()

    def add_root_cert(self, **kwargs):
        assetsource_logger.debug("Method: add_root_cert")
        try:
            username = kwargs['ssh_username']
            password = kwargs['ssh_password']
            base64_cert = kwargs['base64_cert']
        except KeyError as e:
            assetsource_logger.error(f"Missing required field: {e}")
            raise exceptions.PpdmException(f"Missing required field: {e}")
        command = ("/usr/local/brs/bin/ppdmtool -importcert -alias "
                   f"{self.name} -file /home/admin/cert.pem -type BASE64")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(self.server, username=username, password=password)
        except paramiko.ssh_exception.AuthenticationException as authError:
            raise exceptions.PpdmException("Invalid auth credentials: "
                                           f"{authError}")
        ftp = ssh.open_sftp()
        file = ftp.file('cert.pem', 'w', -1)
        file.write(base64_cert)
        file.flush()
        ftp.close()
        stdin, stdout, stderr = ssh.exec_command(command, timeout=30)
        error = stderr.read()
        error = error.decode("utf-8")
        output = stdout.read()
        output = output.decode("utf-8")
        ssh.close()
        if not ("Certificate was added to keystore" in error or
                "already exists" in output):
            assetsource_logger.error("The certificate was not able to be "
                                     "added to the trust store.")
            assetsource_logger.error(f"stderr: {error}")
            assetsource_logger.error(f"stdout: {output}")
            return False
        assetsource_logger.debug("Certificate was successfully added")
        return True

    def __get_asset_source_discovery(self):
        assetsource_logger.debug("Method: __get_asset_source_discovery")
        response = super()._rest_get("/discoveries?filter=start%20eq%20%22%2F"
                                     f"inventory-sources%2F{self.id}%22")
        if not response.json()['content']:
            assetsource_logger.error("Unable to find discovery schedule")
        self.discovery = response.json()['content'][0]

    def __update_asset_source_discovery(self):
        assetsource_logger.debug("Method: __update_asset_source_discovery")
        response = super()._rest_put(f"/discoveries/{self.discovery['id']}",
                                     self.discovery)
        if not response.ok:
            assetsource_logger.error("Unable to update discovery id: "
                                     f"{self.discovery['id']}")

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
                assetsource_logger.debug(err_msg)
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
        if not certificate.response['state'] == 'ACCEPTED':
            assetsource_logger.debug("Cert not accepted. Accepting now")
            self.__accept_host_certificate(certificate.response)
        credential_id = kwargs.get('credential_id', '')
        if not credential_id:
            credential = Credential(name=kwargs['credential_name'],
                                    server=self.server,
                                    token=self._token)
            credential_id = credential.id
        body = {}
        body['address'] = kwargs['address']
        body['name'] = self.name
        body['port'] = kwargs['port']
        body['type'] = kwargs['asset_type']
        vcenter_id = kwargs.get('vcenter_id', '')
        body.update({'credentials': {'id': credential_id}})
        if kwargs['asset_type'] == 'KUBERNETES' and kwargs['tanzu']:
            if not vcenter_id:
                vcenter = self.__get_assetsource_by_name(name=kwargs
                                                         ['vcenter_name'])
                vcenter_id = vcenter.response['id']
            if not vcenter_id:
                raise exceptions.PpdmException("Invalid or missing: "
                                               "vcenter_name or vcenter_id")
            body.update({'details':
                         {'k8s':
                          {'vCenterId': vcenter_id}}})
        if kwargs['asset_type'] == 'VCENTER':
            body.update({'details':
                         {'vCenter':
                          {'vSphereUiIntegration':
                           kwargs['enable_vsphere_integration']}}})
        response = super()._rest_post("/inventory-sources", body)
        if response.ok:
            msg = f"Assetsource id \"{self.name}\" " \
                   "successfully created"
            self.id = response.json()['id']
            self.__get_asset_source_discovery()
            self.discovery['schedule']['enabled'] = True
            self.__update_asset_source_discovery()
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
        response = super()._rest_get(f"/certificates?host={address}&"
                                     f"port={port}&type=Root")
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
