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

use Closure;
use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\Configuration\PrivateKey;
use SimpleSAML\XMLSecurity\Alg\Signature\PrivateKeyAgentRSA;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Exception\UnsupportedAlgorithmException;
use SimpleSAML\XMLSecurity\Key\PrivateKey as LocalPrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Exception\RuntimeException;
use TypeError;

/**
 * RSA-SHA256/384/512 signers for hosted entities: the private key agent for an agent identity, its local key otherwise.
 *
 * Every entry point signs with RSA-SHA256 unless another supported algorithm is passed; an unsupported or blacklisted
 * algorithm fails with an UnsupportedAlgorithmException instead of being replaced. An agent identity never reads a
 * private key file, so an agent failure cannot turn into a local signature.
 *
 * @SuppressWarnings("PHPMD.CouplingBetweenObjects")
 */
final class Signers
{
    public const string DEFAULT_ALGORITHM = C::SIG_RSA_SHA256;

    /**
     * Whether the entry points can sign with the algorithm: RSA-SHA256/384/512, unless blacklisted.
     */
    public static function supports(string $algorithm): bool
    {
        return SignatureAlgorithms::supportsSigning($algorithm);
    }

    /**
     * @throws UnsupportedAlgorithmException when the algorithm is not supported or blacklisted
     */
    public static function forHostedEntity(
        ServiceProvider|IdentityProvider $entity,
        string $algorithm = self::DEFAULT_ALGORITHM,
    ): SignatureAlgorithmInterface {
        return self::select(
            sprintf('The hosted entity "%s"', (string) $entity->getEntityId()),
            $entity->usesPrivateKeyAgent(),
            $algorithm,
            static fn (): ?string => $entity->getCertificateFile(),
            static function () use ($entity, $algorithm): SignatureAlgorithmInterface {
                $privateKey = $entity->getPrivateKey(PrivateKey::NAME_DEFAULT);
                if (!$privateKey instanceof PrivateKey) {
                    throw new RuntimeException(sprintf(
                        'The hosted entity "%s" has no default private key configured',
                        (string) $entity->getEntityId()
                    ));
                }

                return self::forPrivateKey($privateKey, null, $algorithm);
            }
        );
    }

    /**
     * @throws UnsupportedAlgorithmException when the algorithm is not supported or blacklisted
     */
    public static function forKeyPair(
        KeyPair $keyPair,
        ?PrivateKeyLoader $privateKeyLoader = null,
        string $algorithm = self::DEFAULT_ALGORITHM,
    ): SignatureAlgorithmInterface {
        return self::select(
            'The metadata signing key pair',
            $keyPair->usePrivateKeyAgent,
            $algorithm,
            static fn (): string => $keyPair->publicKeyFile,
            static function () use ($keyPair, $privateKeyLoader, $algorithm): SignatureAlgorithmInterface {
                if (!is_string($keyPair->privateKeyFile) || $keyPair->privateKeyFile === '') {
                    throw new RuntimeException('No private key file is configured for signing');
                }

                return self::forPrivateKey(new PrivateKey($keyPair->privateKeyFile, 'metadata'), $privateKeyLoader, $algorithm);
            }
        );
    }

    /**
     * @param Closure(): ?string $certificateFile Never invoked for a local identity.
     * @param Closure(): SignatureAlgorithmInterface $localSigner Never invoked for an agent identity.
     */
    private static function select(
        string $identity,
        bool $useAgent,
        string $algorithm,
        Closure $certificateFile,
        Closure $localSigner,
    ): SignatureAlgorithmInterface {
        // Checked first, so an unsupported algorithm fails before any key or certificate file is read.
        self::assertSupported($algorithm);

        if ($useAgent) {
            $file = $certificateFile();
            if ($file === null || $file === '') {
                throw new RuntimeException(sprintf('%s uses the private key agent but has no certificate file', $identity));
            }

            return self::forAgentCertificate($file, $algorithm);
        }

        return $localSigner();
    }

    /**
     * @throws UnsupportedAlgorithmException when the algorithm is not supported or blacklisted
     */
    public static function forPrivateKey(
        PrivateKey $privateKey,
        ?PrivateKeyLoader $loader = null,
        string $algorithm = self::DEFAULT_ALGORITHM,
    ): SignatureAlgorithmInterface {
        self::assertSupported($algorithm);

        return self::forLocalKey(($loader ?? new PrivateKeyLoader())->loadPrivateKey($privateKey), $algorithm);
    }

    /**
     * @throws UnsupportedAlgorithmException when the algorithm is not supported or blacklisted
     */
    public static function forLocalKey(
        LocalPrivateKey $privateKey,
        string $algorithm = self::DEFAULT_ALGORITHM,
    ): SignatureAlgorithmInterface {
        return SignatureAlgorithms::forSigning($algorithm, $privateKey);
    }

    /**
     * A signer that sends the signature operation for the certificate's key to the private key agent.
     *
     * @throws UnsupportedAlgorithmException when the algorithm is not supported or blacklisted
     */
    public static function forAgentCertificate(
        string $certificateFile,
        string $algorithm = self::DEFAULT_ALGORITHM,
    ): SignatureAlgorithmInterface {
        self::assertSupported($algorithm);
        $certificate = X509Certificate::fromFile($certificateFile);
        $notRegistered = sprintf('The private key agent is not registered for "%s" signatures', $algorithm);

        try {
            $signer = SignatureAlgorithms::forSigning($algorithm, $certificate);
        } catch (TypeError $exception) {
            // The default RSA class only accepts key material, so this means no agent wrapper is registered.
            throw new RuntimeException($notRegistered, 0, $exception);
        }

        if (!$signer instanceof PrivateKeyAgentRSA) {
            throw new RuntimeException($notRegistered);
        }

        return $signer;
    }

    private static function assertSupported(string $algorithm): void
    {
        if (!self::supports($algorithm)) {
            throw new UnsupportedAlgorithmException(sprintf('Unsupported or blacklisted signing algorithm "%s"', $algorithm));
        }
    }
}
