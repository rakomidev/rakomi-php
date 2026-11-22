<?php

declare(strict_types=1);

namespace Rakomi;

/** Raised when discovery or JWKS retrieval fails or returns an untrustworthy document. */
final class DiscoveryException extends \RuntimeException
{
}
