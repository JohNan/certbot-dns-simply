# certbot-dns-simply

Simply.com DNS Authenticator plugin for Certbot.

## Installation

```sh
pip install certbot-dns-simply
```

## Usage

To start using DNS authentication for the Simply.com DNS API, pass the following arguments on certbot's command line:

| Option                       | Description                                         |
|------------------------------|-----------------------------------------------------|
| `--authenticator dns-simply` | select the authenticator plugin (Required)          |
| `--dns-simply-credentials`   | Simply.com DNS API credentials INI file. (Required) |

## Credentials

The plugin authenticates with the API key of your Simply.com account, sent as a Bearer token (see the [Simply.com API documentation](https://www.simply.com/en/docs/api/)).
API keys are created in the Simply.com control panel under Account, API keys.
Please make sure to use the absolute path - some users experienced problems with relative paths.

An example `credentials.ini` file:

```ini
dns_simply_api_key = DSHJdsjh2812872sahj
```

`dns_simply_account_name` is no longer needed. Existing credentials files that still contain it keep working; the value is ignored.

## Examples
To acquire a certificate for `example.com`

```bash
certbot certonly \
 --authenticator dns-simply \
 --dns-simply-credentials /path/to/my/credentials.ini \
 -d example.com
```

To acquire a certificate for ``*.example.com``
```bash
   certbot certonly \
     --authenticator dns-simply \
     --dns-simply-credentials /path/to/my/credentials.ini \
     -d '*.example.com'
```
