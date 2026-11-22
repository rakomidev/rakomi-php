<?php

declare(strict_types=1);

namespace Rakomi\Tests;

use PHPUnit\Framework\TestCase;
use Rakomi\Discovery;
use Rakomi\DiscoveryException;

final class DiscoveryTest extends TestCase
{
    private const ISSUER = 'https://issuer.example';

    /** @param array<string, string> $responses */
    private static function fetcher(array $responses, array &$calls = []): callable
    {
        return static function (string $url) use ($responses, &$calls): string {
            $calls[] = $url;
            return $responses[$url] ?? throw new DiscoveryException('unexpected url');
        };
    }

    /** @return array<string, mixed> */
    private static function metadata(array $override = []): array
    {
        return $override + [
            'issuer' => self::ISSUER,
            'jwks_uri' => self::ISSUER . '/jwks.json',
            'token_endpoint' => self::ISSUER . '/token',
        ];
    }

    private static function jwks(): string
    {
        return json_encode(['keys' => [['kty' => 'EC', 'kid' => 'k1']]], JSON_THROW_ON_ERROR);
    }

    /** @param array<string, mixed> $meta */
    private static function discoverWith(array $meta, ?string $jwks = null, string $issuer = self::ISSUER): array
    {
        return Discovery::discover($issuer, self::fetcher([
            self::ISSUER . Discovery::WELL_KNOWN_PATH => json_encode($meta, JSON_THROW_ON_ERROR),
            self::ISSUER . '/jwks.json' => $jwks ?? self::jwks(),
        ]));
    }

    public function testReturnsMetadataWithKeySet(): void
    {
        $calls = [];
        $result = Discovery::discover(self::ISSUER . '/', self::fetcher([
            self::ISSUER . Discovery::WELL_KNOWN_PATH => json_encode(self::metadata(), JSON_THROW_ON_ERROR),
            self::ISSUER . '/jwks.json' => self::jwks(),
        ], $calls));

        self::assertSame(self::ISSUER, $result['issuer']);
        self::assertSame('k1', $result['jwks']['keys'][0]['kid']);
        self::assertSame([
            self::ISSUER . Discovery::WELL_KNOWN_PATH,
            self::ISSUER . '/jwks.json',
        ], $calls);
    }

    public function testRejectsNonHttpsIssuer(): void
    {
        $this->expectException(DiscoveryException::class);
        Discovery::discover('http://issuer.example', self::fetcher([]));
    }

    public function testRejectsIssuerWithQuery(): void
    {
        $this->expectException(DiscoveryException::class);
        Discovery::discover(self::ISSUER . '?a=b', self::fetcher([]));
    }

    public function testRejectsIssuerMismatch(): void
    {
        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage('issuer does not match');
        self::discoverWith(self::metadata(['issuer' => 'https://other.example']));
    }

    /** @return iterable<string, array{string}> */
    public static function requiredFields(): iterable
    {
        foreach (['issuer', 'jwks_uri', 'token_endpoint'] as $f) {
            yield $f => [$f];
        }
    }

    /** @dataProvider requiredFields */
    public function testRejectsMissingRequiredField(string $field): void
    {
        $meta = self::metadata();
        unset($meta[$field]);
        $this->expectException(DiscoveryException::class);
        $this->expectExceptionMessage("'$field'");
        self::discoverWith($meta);
    }

    public function testRejectsNonHttpsJwksUri(): void
    {
        $this->expectException(DiscoveryException::class);
        self::discoverWith(self::metadata(['jwks_uri' => 'http://issuer.example/jwks.json']));
    }

    public function testRejectsEmptyKeySet(): void
    {
        $this->expectException(DiscoveryException::class);
        self::discoverWith(self::metadata(), '{"keys":[]}');
    }

    public function testRejectsInvalidJson(): void
    {
        $this->expectException(DiscoveryException::class);
        self::discoverWith(self::metadata(), 'not json');
    }

    public function testRejectsNonObjectDocument(): void
    {
        $this->expectException(DiscoveryException::class);
        Discovery::discover(self::ISSUER, static fn (): string => '[]');
    }

    public function testRejectsOversizedBody(): void
    {
        $this->expectException(DiscoveryException::class);
        Discovery::discover(self::ISSUER, static fn (): string => str_repeat('a', Discovery::MAX_BODY_BYTES + 1));
    }

    public function testFetcherErrorPropagates(): void
    {
        $this->expectException(DiscoveryException::class);
        Discovery::discover(self::ISSUER, static function (string $url): string {
            throw new DiscoveryException('Request failed.');
        });
    }

    public function testDefaultFetcherRefusesHttp(): void
    {
        $this->expectException(DiscoveryException::class);
        Discovery::fetch('http://issuer.example/x');
    }
}
