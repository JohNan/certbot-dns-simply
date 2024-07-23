import unittest
from unittest.mock import patch, MagicMock
import requests_mock
from certbot.errors import PluginError
from your_script_name import SimplyAuthenticator, SimplyClient


class TestSimplyAuthenticator(unittest.TestCase):
    def setUp(self):
        self.authenticator = SimplyAuthenticator(config=None, name="simply")

    @patch("your_script_name.SimplyClient")
    def test_perform(self, mock_client):
        mock_client_instance = mock_client.return_value
        self.authenticator._setup_credentials = MagicMock()
        self.authenticator.credentials = MagicMock()
        self.authenticator.credentials.conf.return_value = "mock_value"
        self.authenticator._get_simply_client = MagicMock(return_value=mock_client_instance)

        achall = MagicMock()
        achall.domain = "example.com"
        achall.validation.return_value = "test_validation"

        self.authenticator._perform("example.com", "_acme-challenge.example.com", "test_validation")

        mock_client_instance.add_txt_record.assert_called_with("example.com", "_acme-challenge.example.com", "test_validation")

    @patch("your_script_name.SimplyClient")
    def test_cleanup(self, mock_client):
        mock_client_instance = mock_client.return_value
        self.authenticator._setup_credentials = MagicMock()
        self.authenticator.credentials = MagicMock()
        self.authenticator.credentials.conf.return_value = "mock_value"
        self.authenticator._get_simply_client = MagicMock(return_value=mock_client_instance)

        achall = MagicMock()
        achall.domain = "example.com"
        achall.validation.return_value = "test_validation"

        self.authenticator._cleanup("example.com", "_acme-challenge.example.com", "test_validation")

        mock_client_instance.del_txt_record.assert_called_with("example.com", "_acme-challenge.example.com", "test_validation")


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
        mock.delete(f"https://api.simply.com/2/my/products/{self.domain}/dns/records/123/", status_code=400, text="Error")

        with self.assertRaises(PluginError):
            self.client.del_txt_record(self.domain, f"{self.sub_domain}.{self.domain}", "test_validation")


if __name__ == "__main__":
    unittest.main()
