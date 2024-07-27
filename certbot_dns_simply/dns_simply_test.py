import unittest
from unittest.mock import patch, MagicMock
from unittest import mock
import requests_mock
from certbot.compat import os
from certbot.errors import PluginError
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

from certbot_dns_simply.dns_simply import Authenticator, SimplyClient

patch_display_util = test_util.patch_display_util

FAKE_RECORD = {
    "record": {
        "id": "123Fake",
    }
}


class TestAuthenticator(
    test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest
):
    def setUp(self):
        super().setUp()
        path = os.path.join(self.tempdir, "fake_credentials.ini")
        dns_test_common.write(
            {
                "simply_account_name": "account_name",
                "simply_api_key": "api_key",
            },
            path,
        )

        super().setUp()
        self.config = mock.MagicMock(
            simply_credentials=path, simply_propagation_seconds=0
        )

        self.mock_client = mock.MagicMock()

        mock_client_wrapper = mock.MagicMock()
        mock_client_wrapper.__enter__ = mock.MagicMock(
            return_value=self.mock_client
        )

        self.auth = Authenticator(config=None, name="simply")
        self.auth._get_simply_client = mock.MagicMock(
            return_value=mock_client_wrapper
        )

    @patch("certbot_dns_simply.dns_simply.SimplyClient")
    def test_perform_old(self, mock_client):
        mock_client_instance = mock_client.return_value
        self.auth._setup_credentials = MagicMock()
        self.auth.credentials = MagicMock()
        self.auth.credentials.conf.return_value = "mock_value"
        self.auth._get_simply_client = MagicMock(return_value=mock_client_instance)

        achall = MagicMock()
        achall.domain = "example.com"
        achall.validation.return_value = "test_validation"

        self.auth._perform("example.com", "_acme-challenge.example.com", "test_validation")

        mock_client_instance.add_txt_record.assert_called_with("example.com", "_acme-challenge.example.com",
                                                               "test_validation")

    @patch_display_util()
    def test_perform(self, _unused_mock_get_utility):
        self.mock_client.create_record.return_value = FAKE_RECORD
        self.auth.perform([self.achall])
        self.mock_client.create_record.assert_called_with(
            "TXT", "_acme-challenge." + DOMAIN + ".", mock.ANY
        )

    def test_perform_but_raises_plugin_error(self):
        self.mock_client.create_record.side_effect = mock.MagicMock(
            side_effect=PluginError()
        )
        self.assertRaises(PluginError, self.auth.perform, [self.achall])
        self.mock_client.create_record.assert_called_with(
            "TXT", "_acme-challenge." + DOMAIN + ".", mock.ANY
        )

    def test_perform_but_raises_plugin_error(self):
        self.mock_client.create_record.side_effect = mock.MagicMock(
            side_effect=PluginError()
        )
        self.assertRaises(PluginError, self.auth.perform, [self.achall])
        self.mock_client.create_record.assert_called_with(
            "TXT", "_acme-challenge." + DOMAIN + ".", mock.ANY
        )

    @patch("certbot_dns_simply.dns_simply.SimplyClient")
    def test_cleanup(self, mock_client):
        mock_client_instance = mock_client.return_value
        self.auth._setup_credentials = MagicMock()
        self.auth.credentials = MagicMock()
        self.auth.credentials.conf.return_value = "mock_value"
        self.auth._get_simply_client = MagicMock(return_value=mock_client_instance)

        achall = MagicMock()
        achall.domain = "example.com"
        achall.validation.return_value = "test_validation"

        self.auth._cleanup("example.com", "_acme-challenge.example.com", "test_validation")

        mock_client_instance.del_txt_record.assert_called_with("example.com", "_acme-challenge.example.com",
                                                               "test_validation")


class TestSimplyClient(unittest.TestCase):
    def setUp(self):
        self.client = SimplyClient("account_name", "api_key")
        self.domain = "example.com"
        self.sub_domain = "_acme-challenge"

    @requests_mock.Mocker()
    def test_add_txt_record(self, mock):
        mock.post(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/", status_code=200)
        self.client.add_txt_record(self.domain, f"{self.sub_domain}.{self.domain}", "test_validation")
        self.assertTrue(mock.called)

    @requests_mock.Mocker()
    def test_del_txt_record(self, mock):
        mock.get(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/", json=[
            {"record_id": 123, "type": "TXT", "name": self.sub_domain, "data": "test_validation"}
        ])
        mock.delete(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/123/", status_code=200)

        self.client.del_txt_record(self.domain, f"{self.sub_domain}.{self.domain}", "test_validation")
        self.assertTrue(mock.called)

    @requests_mock.Mocker()
    def test_add_txt_record_fail(self, mock):
        mock.post(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/", status_code=400, text="Error")

        with self.assertRaises(PluginError):
            self.client.add_txt_record(self.domain, f"{self.sub_domain}.{self.domain}", "test_validation")

    @requests_mock.Mocker()
    def test_del_txt_record_fail(self, mock):
        mock.get(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/", json=[
            {"record_id": 123, "type": "TXT", "name": self.sub_domain, "data": "test_validation"}
        ])
        mock.delete(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/123/", status_code=400,
                    text="Error")

        with self.assertRaises(PluginError):
            self.client.del_txt_record(self.domain, f"{self.sub_domain}.{self.domain}", "test_validation")


if __name__ == "__main__":
    unittest.main()
