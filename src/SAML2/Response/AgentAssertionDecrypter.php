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

namespace Surfnet\SamlBundle\SAML2\Response;

use Closure;
use Psr\Log\LoggerInterface;
use SimpleSAML\SAML2\Assertion\Exception\InvalidAssertionException;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\EncryptedAssertion;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\PrivateKeyAgentRSA as PrivateKeyAgentKeyTransport;
use SimpleSAML\XMLSecurity\Exception\InvalidRequestException as AgentInvalidRequestException;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use SimpleSAML\XMLSecurity\XML\ds\X509Certificate as X509CertificateElement;
use SimpleSAML\XMLSecurity\XML\ds\X509Data;
use SimpleSAML\XMLSecurity\XML\xenc\EncryptedKey;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\PrivateKeyAgent\AgentOperation;
use Surfnet\SamlBundle\PrivateKeyAgent\KeyMap;
use Throwable;

/**
 * Selects the backend per identity; only an agent HTTP 400 advances to the next rollover key.
 *
 * @SuppressWarnings("PHPMD.CouplingBetweenObjects")
 */
final readonly class AgentAssertionDecrypter implements AssertionDecrypter
{
    /**
     * @param Closure(): KeyMap $keyMap Resolved only when an agent identity needs decryption.
     */
    public function __construct(
        private AssertionDecrypter $localDecrypter,
        private Closure $keyMap,
        private LoggerInterface $logger,
    ) {
    }

    public function decrypt(
        EncryptedAssertion $encryptedAssertion,
        ServiceProvider $serviceProvider,
        IdentityProvider $identityProvider,
    ): Assertion {
        if (!$serviceProvider->usesPrivateKeyAgent()) {
            return $this->localDecrypter->decrypt($encryptedAssertion, $serviceProvider, $identityProvider);
        }

        $transport = new EncryptedAssertionKey($encryptedAssertion);
        $certificates = ($this->keyMap)()->certificatesFor(AgentOperation::DECRYPT);
        if ($certificates === []) {
            throw new InvalidAssertionException('The service provider uses the private key agent, but no agent key may decrypt');
        }

        $named = self::namedCertificateFingerprints($transport->encryptedKey);
        if ($named !== []) {
            $certificates = array_values(array_filter(
                $certificates,
                static fn (X509Certificate $certificate): bool => in_array(KeyMap::fingerprintOf($certificate), $named, true)
            ));
            if ($certificates === []) {
                throw new InvalidAssertionException('The EncryptedKey names a certificate that no agent decryption key has');
            }
        }

        $lastException = null;
        foreach ($certificates as $certificate) {
            try {
                $decryptor = $transport->factory->getAlgorithm($transport->algorithm, $certificate);
            } catch (Throwable $exception) {
                throw new InvalidAssertionException(sprintf(
                    'The private key agent could not initialize key transport for "%s"',
                    $transport->algorithm
                ), 0, $exception);
            }
            if (!$decryptor instanceof PrivateKeyAgentKeyTransport) {
                throw new InvalidAssertionException(sprintf('The private key agent is not registered for "%s"', $transport->algorithm));
            }

            try {
                return $encryptedAssertion->decrypt($decryptor);
            } catch (AgentInvalidRequestException $exception) {
                $this->logger->debug(sprintf(
                    'The agent key for certificate %s could not decrypt the assertion',
                    KeyMap::fingerprintOf($certificate)
                ));
                $lastException = $exception;
            }
        }

        throw new InvalidAssertionException('The assertion could not be decrypted with any agent key', 0, $lastException);
    }

    /**
     * @return list<string> SHA-256 fingerprints of the X509Certificates in the KeyInfo of the EncryptedKey
     */
    private static function namedCertificateFingerprints(EncryptedKey $encryptedKey): array
    {
        $fingerprints = [];
        foreach ($encryptedKey->getKeyInfo()?->getInfo() ?? [] as $info) {
            if (!$info instanceof X509Data) {
                continue;
            }
            foreach ($info->getData() as $data) {
                if (!$data instanceof X509CertificateElement) {
                    continue;
                }
                $der = base64_decode(preg_replace('/\s+/', '', $data->getContent()->getValue()) ?? '', true);
                if ($der === false || $der === '') {
                    throw new InvalidAssertionException('The EncryptedKey names an invalid certificate');
                }
                $fingerprints[] = hash('sha256', $der);
            }
        }

        return $fingerprints;
    }
}
