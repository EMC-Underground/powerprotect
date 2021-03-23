class Credential():
    def __init__(self, **kwargs):
        self.name = kwargs['name']
        self.id = ""
        self.username = ""
        self.password = ""
        self.type = ""
        self.method = ""
        self.secret_id = ""
        self.body = {}
        self.target_body = {}
        self.exists = False
        self.changed = False
        self.check_mode = kwargs.get('check_mode', False)
        self.msg = ""
        self.failure = False
        self.fail_msg = ""
        self.fail_response = {}

    def get_credential(self):
        credential = self.__get_credential_by_name()
        if bool(credential.response) is not False:
            self.exists = True
            self.id = credential.response['id']
            self.secretId = credential.response['secretId']
        else:
            self.exists = False
            self.id = ""
            self.secretId = ""
        self.body = credential.response
