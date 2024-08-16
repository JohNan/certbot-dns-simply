"""DNS Authenticator for Simply.com"""

import base64
from contextlib import AbstractContextManager

import requests
from certbot.errors import PluginError
from certbot.plugins.dns_common import DNSAuthenticator


class Authenticator(DNSAuthenticator):
    """DNS Authenticator for Simply.com
    This Authenticator uses the Simply.com API to fulfill a dns-01 challenge.
    """

    description = (
        "Obtain certificates using a DNS TXT record (DNS-01 challenge) with Simply.com"
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds=60):
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=default_propagation_seconds
        )
        add("credentials", help="Simply.com API credentials INI file.")

    def more_info(self):
        return "This plugin configures a DNS TXT record to respond to a DNS-01 challenge using the Simply.com API."

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "Simply.com API credentials INI file",
            {
                "account_name": "Account name for Simply.com API",
                "api_key": "API key for Simply.com API",
            },
        )

    def _perform(self, domain, validation_name, validation):
        with self._get_simply_client() as client:
            client.add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        with self._get_simply_client() as client:
            client.del_txt_record(domain, validation_name, validation)

    def _get_simply_client(self):
        return SimplyClient(
            self.credentials.conf("account_name"),
            self.credentials.conf("api_key"),
        )


def get_product_name(domain):
    """Extract the product name from the domain."""
    parts = domain.split(".")
    if len(parts) < 2:
        return domain

    return ".".join(parts[-2:])


class SimplyClient(AbstractContextManager):
    """Encapsulates all communication with the Simply.com API."""

    API_URL = "https://api.simply.com/2"

    def __init__(self, account_name, api_key):
        self.account_name = account_name
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Basic {self._base64_encode(f'{account_name}:{api_key}')}",
            "Content-Type": "application/json",
        }
        self.session = requests.Session()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.close()

    def add_txt_record(self, domain, validation_name, validation):
        """Add a TXT record using the supplied information."""
        product = get_product_name(domain)

        data = {
            "name": validation_name,
            "type": "TXT",
            "data": validation,
            "priority": 0,
            "ttl": 3600,
        }
        try:
            self._request("POST", f"/my/products/{product}/dns/records/", data)
        except requests.exceptions.RequestException as exp:
            raise PluginError(f"Error adding TXT record: {exp}") from exp

    def del_txt_record(self, domain, validation_name, validation):
        """Delete a TXT record using the supplied information."""
        product = get_product_name(domain)

        response = self._request("GET", f"/my/products/{product}/dns/records/")

        for record in response["records"]:
            if (
                record["type"] == "TXT"
                and record["name"] == validation_name
                and record["data"] == validation
            ):
                try:
                    self._request(
                        "DELETE",
                        f"/my/products/{product}/dns/records/{record['record_id']}/",
                    )
                except requests.exceptions.RequestException as exp:
                    raise PluginError(f"Error deleting TXT record: {exp}") from exp

    @staticmethod
    def _split_domain(validation_name, domain):
        validation_name = validation_name.replace(f".{domain}", "")
        return validation_name, domain

    @staticmethod
    def _base64_encode(data):
        return base64.b64encode(data.encode()).decode()

    def _request(self, method, endpoint, data=None):
        url = f"{self.API_URL}{endpoint}"
        response = requests.request(
            method, url, headers=self.headers, json=data, timeout=30
        )
        response.raise_for_status()
        return response.json()
