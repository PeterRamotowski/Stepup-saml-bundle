<?php declare(strict_types=1);

/**
 * Copyright 2026 SURFnet B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Surfnet\SamlBundle\Signing;

use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\XMLSecurity\Alg\Signature\RSA;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Exception\UnsupportedAlgorithmException;
use SimpleSAML\XMLSecurity\Key\KeyInterface;
use SimpleSAML\XMLSecurity\Key\PublicKey;

/**
 * @internal
 */
final class SignatureAlgorithms
{
    /**
     * RSA PKCS#1 v1.5 with SHA-256/384/512: the outbound signature methods and the HTTP-Redirect verification methods.
     */
    private const array RSA_SHA2 = [C::SIG_RSA_SHA256, C::SIG_RSA_SHA384, C::SIG_RSA_SHA512];

    public static function supportsSigning(string $algorithm): bool
    {
        return self::isAllowedRsaSha2($algorithm);
    }

    public static function forSigning(string $algorithm, KeyInterface $key): SignatureAlgorithmInterface
    {
        if (!self::supportsSigning($algorithm)) {
            throw new UnsupportedAlgorithmException(sprintf('Unsupported or blacklisted signing algorithm "%s"', $algorithm));
        }

        return self::factory()->getAlgorithm($algorithm, $key);
    }

    /**
     * The check RedirectBinding applies before verification; it matches forRedirectVerification() exactly.
     */
    public static function supportsRedirectVerification(string $algorithm): bool
    {
        return self::isAllowedRsaSha2($algorithm);
    }

    public static function forRedirectVerification(string $algorithm, PublicKey $key): SignatureAlgorithmInterface
    {
        if (!self::supportsRedirectVerification($algorithm)) {
            throw new UnsupportedAlgorithmException(
                sprintf('Unsupported or blacklisted Redirect signature algorithm "%s"', $algorithm)
            );
        }

        return self::forVerification($algorithm, $key);
    }

    public static function forVerification(string $algorithm, PublicKey $key): SignatureAlgorithmInterface
    {
        if (!in_array($algorithm, RSA::getSupportedAlgorithms(), true)) {
            throw new UnsupportedAlgorithmException(sprintf('Unsupported RSA signature algorithm "%s"', $algorithm));
        }

        return self::factory()->getAlgorithm($algorithm, $key);
    }

    /**
     * A factory that honours the algorithm blacklist of the installed saml2 container.
     */
    public static function factory(): SignatureAlgorithmFactory
    {
        return new SignatureAlgorithmFactory(self::blacklist());
    }

    private static function isAllowedRsaSha2(string $algorithm): bool
    {
        return in_array($algorithm, self::RSA_SHA2, true) && !in_array($algorithm, self::blacklist(), true);
    }

    /**
     * @return string[]
     */
    private static function blacklist(): array
    {
        return ContainerSingleton::getInstance()->getBlacklistedEncryptionAlgorithms()
            ?? SignatureAlgorithmFactory::DEFAULT_BLACKLIST;
    }
}
