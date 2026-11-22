# rakomi/sdk

PHP SDK for [Rakomi](https://rakomi.com), EU-native authentication as a service.

This first release provides OpenID Connect discovery: it reads an issuer's
metadata and signing keys so that your application can validate tokens.

## Install

```bash
composer require rakomi/sdk
```

Requires PHP 8.1 or later with `ext-curl` and `ext-json`.

## Usage

```php
use Rakomi\Discovery;
use Rakomi\DiscoveryException;

try {
    $config = Discovery::discover('https://api.rakomi.com');
} catch (DiscoveryException $e) {
    // The issuer could not be reached or returned an untrustworthy document.
}

$config['token_endpoint'];
$config['jwks']['keys']; // JSON Web Key Set
```

`Discovery::discover()`:

- accepts https issuers only and never follows redirects;
- requires the returned `issuer` to equal the one you asked for;
- requires `issuer`, `jwks_uri` and `token_endpoint`, and https URLs for endpoints;
- applies a 5 second timeout and a 1 MiB size limit per request.

To use your own HTTP client, pass a callable as the second argument. It receives
an https URL and returns the response body, or throws `DiscoveryException`.

## Development

```bash
composer install
composer test
```

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
