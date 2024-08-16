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

Username is the Simply.com account-number (Sxxxxxx) and the password is the API-KEY for the specific account.
The API-Key assigned to your Simply.com account can be found in your Simply.com Controlpanel.
Please make sure to use the absolute path - some users experienced problems with relative paths.

An example `credentials.ini` file:

```ini
dns_simply_account_name = Sxxxxxx
dns_simply_api_key = DSHJdsjh2812872sahj
```

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
