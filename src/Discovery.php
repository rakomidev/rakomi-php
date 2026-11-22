<?php

declare(strict_types=1);

namespace Rakomi;

/**
 * OpenID Connect discovery for a Rakomi issuer.
 *
 * Fetches `{issuer}/.well-known/openid-configuration` and the document's `jwks_uri`
 * over HTTPS only, checks that the document names the issuer that was asked for,
 * and returns the metadata with the key set under `jwks`.
 */
final class Discovery
{
    public const WELL_KNOWN_PATH = '/.well-known/openid-configuration';
    public const TIMEOUT_SECONDS = 5;
    public const MAX_BODY_BYTES = 1048576;

    private const REQUIRED_FIELDS = ['issuer', 'jwks_uri', 'token_endpoint'];
    private const URL_FIELDS = ['jwks_uri', 'token_endpoint', 'authorization_endpoint'];

    /**
     * @param string $issuer Issuer identifier, an https URL without query or fragment.
     * @param (callable(string): string)|null $fetcher Returns the body of an https GET
     *        or throws DiscoveryException. Defaults to a cURL fetcher without redirects.
     * @return array<string, mixed> Discovery metadata plus the key set under `jwks`.
     * @throws DiscoveryException
     */
    public static function discover(string $issuer, ?callable $fetcher = null): array
    {
        $issuer = self::normalizeIssuer($issuer);
        $fetcher ??= [self::class, 'fetch'];

        $metadata = self::decode(self::get($fetcher, $issuer . self::WELL_KNOWN_PATH), 'discovery document');

        foreach (self::REQUIRED_FIELDS as $field) {
            if (!isset($metadata[$field]) || !is_string($metadata[$field]) || $metadata[$field] === '') {
                throw new DiscoveryException("Discovery document is missing '$field'.");
            }
        }
        if ($metadata['issuer'] !== $issuer) {
            throw new DiscoveryException('Discovery document issuer does not match the requested issuer.');
        }
        foreach (self::URL_FIELDS as $field) {
            if (isset($metadata[$field])) {
                self::assertHttps($metadata[$field], $field);
            }
        }

        $jwks = self::decode(self::get($fetcher, $metadata['jwks_uri']), 'key set');
        if (!isset($jwks['keys']) || !is_array($jwks['keys']) || $jwks['keys'] === [] || !array_is_list($jwks['keys'])) {
            throw new DiscoveryException("Key set is missing a non-empty 'keys' array.");
        }

        $metadata['jwks'] = $jwks;
        return $metadata;
    }

    /** @internal Default fetcher: HTTPS GET without redirects, bounded time and size. */
    public static function fetch(string $url): string
    {
        self::assertHttps($url, 'url');
        $ch = curl_init($url);
        if ($ch === false) {
            throw new DiscoveryException('Could not initialise the HTTP client.');
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => self::TIMEOUT_SECONDS,
            CURLOPT_TIMEOUT => self::TIMEOUT_SECONDS,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_MAXFILESIZE => self::MAX_BODY_BYTES,
        ]);
        $body = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $failed = $body === false;
        curl_close($ch);

        if ($failed || !is_string($body)) {
            throw new DiscoveryException('Request failed.');
        }
        if ($status !== 200) {
            throw new DiscoveryException("Unexpected HTTP status $status.");
        }
        return $body;
    }

    private static function normalizeIssuer(string $issuer): string
    {
        $issuer = rtrim($issuer, '/');
        self::assertHttps($issuer, 'issuer');
        $parts = parse_url($issuer);
        if ($parts === false || isset($parts['query']) || isset($parts['fragment'])) {
            throw new DiscoveryException('Issuer must not contain a query or fragment.');
        }
        return $issuer;
    }

    private static function assertHttps(mixed $url, string $name): void
    {
        $parts = is_string($url) ? parse_url($url) : false;
        if (
            $parts === false
            || strtolower($parts['scheme'] ?? '') !== 'https'
            || ($parts['host'] ?? '') === ''
            || isset($parts['user'])
            || isset($parts['pass'])
        ) {
            throw new DiscoveryException("'$name' must be an https URL.");
        }
    }

    /** @param callable(string): string $fetcher */
    private static function get(callable $fetcher, string $url): string
    {
        $body = $fetcher($url);
        if (strlen($body) > self::MAX_BODY_BYTES) {
            throw new DiscoveryException('Response is too large.');
        }
        return $body;
    }

    /** @return array<string, mixed> */
    private static function decode(string $body, string $what): array
    {
        try {
            $data = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new DiscoveryException("The $what is not valid JSON.");
        }
        if (!is_array($data) || array_is_list($data)) {
            throw new DiscoveryException("The $what is not a JSON object.");
        }
        return $data;
    }
}
