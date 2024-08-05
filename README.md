# certbot-dns-simply

Simply.com DNS Authenticator plugin for Certbot.

## Installation

```sh
pip install certbot-dns-simply
```

## Usage
```sh
certbot certonly \\
  --authenticator dns-simply \\
  --certbot-dns-simply:credentials /path/to/credentials.ini \\
  -d yourdomain.com
```