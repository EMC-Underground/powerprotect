import logging
import os


def get_module_logger(mod_name):
    logger = logging.getLogger(mod_name)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
          '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))
    return logger

main_logger = get_module_logger(__name__)

from .ppdm import Ppdm
from .protectionrule import ProtectionRule
from .protectionpolicy import ProtectionPolicy
from .credential import Credential
from .assetsource import AssetSource
from .exceptions import PpdmException
from ._version import __version__

main_logger.debug(f"Module Version: {__version__}")
