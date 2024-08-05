"""Tests for certbot_dns_simply.dns_simply."""

import unittest
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
    """
    Test for Simply DNS Authenticator
    """

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

        self.auth = Authenticator(config=self.config, name="simply")

        self.mock_client = mock.MagicMock()

        mock_client_wrapper = mock.MagicMock()
        mock_client_wrapper.__enter__ = mock.MagicMock(
            return_value=self.mock_client
        )

        # _get_simply_client | pylint: disable=protected-access
        self.auth._get_simply_client = mock.MagicMock(
            return_value=mock_client_wrapper
        )

    @patch_display_util()
    def test_perform(self, _unused_mock_get_utility):
        self.mock_client.add_txt_record.return_value = FAKE_RECORD
        self.auth.perform([self.achall])
        self.mock_client.add_txt_record.assert_called_with(
            DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY
        )

    def test_perform_but_raises_plugin_error(self):
        self.mock_client.add_txt_record.side_effect = mock.MagicMock(
            side_effect=PluginError()
        )
        self.assertRaises(PluginError, self.auth.perform, [self.achall])
        self.mock_client.add_txt_record.assert_called_with(
            DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY
        )

    @patch_display_util()
    def test_cleanup(self, _unused_mock_get_utility):
        self.mock_client.add_txt_record.return_value = FAKE_RECORD
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth.perform([self.achall])
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        self.mock_client.del_txt_record.assert_called_with(
            DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY
        )

    @patch_display_util()
    def test_cleanup_but_raises_plugin_error(self, _unused_mock_get_utility):
        self.mock_client.add_txt_record.return_value = FAKE_RECORD
        self.mock_client.del_txt_record.side_effect = mock.MagicMock(
            side_effect=PluginError()
        )
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth.perform([self.achall])
        self.auth._attempt_cleanup = True

        self.assertRaises(PluginError, self.auth.cleanup, [self.achall])
        self.mock_client.del_txt_record.assert_called_with(
            DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY
        )


class TestSimplyClient(unittest.TestCase):
    """
    Test for Simply API Client
    """

    def setUp(self):
        self.client = SimplyClient("account_name", "api_key")
        self.domain = "example.com"
        self.sub_domain = "_acme-challenge"

    @requests_mock.Mocker()
    def test_add_txt_record(self, request_mock):
        request_mock.post(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/", status_code=200, json=[
            {}
        ])
        self.client.add_txt_record(self.domain, f"{self.sub_domain}.{self.domain}", "test_validation")
        self.assertTrue(request_mock.called)

    @requests_mock.Mocker()
    def test_del_txt_record(self, request_mock):
        request_mock.get(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/", json={
            "records":[
                {"record_id": 123, "type": "TXT", "name": self.sub_domain, "data": "test_validation"},
                {"record_id": 333, "type": "NS", "name": "@", "data": "ns1.simply.com"},
            ]
        })
        request_mock.delete(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/123/", status_code=200,
                            json=[
                                {}
                            ])

        self.client.del_txt_record(self.domain, f"{self.sub_domain}.{self.domain}", "test_validation")
        self.assertTrue(request_mock.called)

    @requests_mock.Mocker()
    def test_add_txt_record_fail(self, request_mock):
        request_mock.post(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/", status_code=400, json=[
            {}
        ])

        with self.assertRaises(PluginError):
            self.client.add_txt_record(self.domain, f"{self.sub_domain}.{self.domain}", "test_validation")

    @requests_mock.Mocker()
    def test_del_txt_record_fail(self, request_mock):
        request_mock.get(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/", json={
            "records":[
                {"record_id": 123, "type": "TXT", "name": self.sub_domain, "data": "test_validation"},
                {"record_id": 333, "type": "NS", "name": "@", "data": "ns1.simply.com"},
            ]
        })
        request_mock.delete(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/123/", status_code=400,
                            text="Error")

        with self.assertRaises(PluginError):
            self.client.del_txt_record(self.domain, f"{self.sub_domain}.{self.domain}", "test_validation")


if __name__ == "__main__":
    unittest.main()
