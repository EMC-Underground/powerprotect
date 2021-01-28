from powerprotect import Ppdm

import mock
import unittest


class RestGetTestCase(unittest.TestCase):

    @mock.patch('powerprotect.requests.get')
    def test_rest_get(self, mock_get):
        mock_get.return_value.status_code = 200
        response = Ppdm.
