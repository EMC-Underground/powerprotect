from powerprotect import get_module_logger

helpers_logger = get_module_logger(__name__)
helpers_logger.propagate = False


class ReturnValue:

    def __init__(self):
        self.success = None
        self.fail_msg = None
        self.status_code = None
        self.response = None


def _body_match(self, server_dict, client_dict):
    combined_dict = {**server_dict, **client_dict}
    return server_dict == combined_dict
