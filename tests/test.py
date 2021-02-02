import sys
sys.path.insert(0, '../powerprotect')

from unittest.mock import Mock, patch
from nose.tools import assert_is_not_none


class RestGetTestCase(unittest.TestCase):

    @patch('powerprotect.requests.get')
    def test_rest_get_good(self, mock_get):
        mock_get.return_value.status_code = 200
        response = Ppdm.
    def test_rest_get_bad(self, m
