from powerprotect import get_module_logger

helpers_logger = get_module_logger(__name__)
helpers_logger.propagate = False


class ReturnBody:

    def __init__(self):
        self.success = bool()
        self.msg = str()
        self.status_code = int()
        self.response = dict()


def _body_match(server_dict, client_dict):
    combined_dict = {**server_dict, **client_dict}
    return server_dict == combined_dict
