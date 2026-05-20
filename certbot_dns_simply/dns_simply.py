"""DNS Authenticator for Simply.com"""

import logging
from contextlib import AbstractContextManager

import requests
from certbot.errors import PluginError
from certbot.plugins import dns_common
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)

ACME_CHALLENGE_TTL = 60


class Authenticator(dns_common.DNSAuthenticator):
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


class SimplyClient(AbstractContextManager):
    """Encapsulates all communication with the Simply.com API."""

    API_URL = "https://api.simply.com/2"

    def __init__(self, account_name, api_key):
        self.account_name = account_name
        self.api_key = api_key
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(account_name, api_key)
        self.session.headers.update({"Content-Type": "application/json"})

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.session.close()

    def add_txt_record(self, domain, validation_name, validation):
        """Add a TXT record using the supplied information."""
        product, _zone = self._find_product(domain)

        data = {
            "name": validation_name,
            "type": "TXT",
            "data": validation,
            "priority": 0,
            "ttl": ACME_CHALLENGE_TTL,
        }
        self._request("POST", f"/my/products/{product}/dns/records/", data)

    def del_txt_record(self, domain, validation_name, validation):
        """Delete a TXT record using the supplied information."""
        product, zone = self._find_product(domain)

        response = self._request("GET", f"/my/products/{product}/dns/records/")

        # The Simply.com API returns record names relative to the zone, e.g.
        # `_acme-challenge.foo` for `_acme-challenge.foo.example.com` on the
        # `example.com` product. Accept both forms so cleanup works regardless
        # of how the API normalises the name on read.
        relative_name = validation_name.removesuffix(f".{zone}")
        accepted_names = {validation_name, relative_name}

        matching = [
            record
            for record in response.get("records", [])
            if record.get("type") == "TXT"
            and record.get("name") in accepted_names
            and record.get("data") == validation
        ]

        if not matching:
            logger.warning(
                "No matching TXT record found to delete for %s on product %s",
                validation_name,
                product,
            )
            return

        for record in matching:
            self._request(
                "DELETE",
                f"/my/products/{product}/dns/records/{record['record_id']}/",
            )

    def _find_product(self, domain: str):
        """Return (object_id, matched_zone_name) for the product that hosts ``domain``."""
        base_domain_guesses = dns_common.base_domain_name_guesses(domain)
        response = self._request("GET", "/my/products/")
        for product in response.get("products", []):
            product_domain = product.get("domain")
            if not product_domain:
                continue
            for key in ("name", "name_idn"):
                zone = product_domain.get(key)
                if zone and zone in base_domain_guesses:
                    return product["object"], zone

        raise PluginError(
            f"No product is matching {base_domain_guesses} for domain {domain}"
        )

    def _request(self, method, endpoint, data=None):
        url = f"{self.API_URL}{endpoint}"
        try:
            response = self.session.request(method, url, json=data, timeout=30)
        except requests.exceptions.RequestException as exp:
            raise PluginError(
                f"Simply.com API request failed ({method} {endpoint}): {exp}"
            ) from exp

        if not response.ok:
            raise PluginError(
                f"Simply.com API error ({method} {endpoint}, HTTP {response.status_code}): "
                f"{_extract_error_message(response)}"
            )

        try:
            return response.json()
        except ValueError as exp:
            raise PluginError(
                f"Simply.com API returned non-JSON response ({method} {endpoint}): {exp}"
            ) from exp


def _extract_error_message(response: requests.Response) -> str:
    """Pull a human-readable message out of a Simply.com error response."""
    try:
        body = response.json()
    except ValueError:
        return response.text.strip() or "no response body"

    if isinstance(body, dict):
        for key in ("error", "message"):
            value = body.get(key)
            if isinstance(value, str) and value:
                return value
    return response.text.strip() or "no response body"
