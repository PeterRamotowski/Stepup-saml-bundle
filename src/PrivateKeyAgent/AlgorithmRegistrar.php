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

namespace Surfnet\SamlBundle\PrivateKeyAgent;

use Closure;
use SimpleSAML\XMLSecurity\Alg\Encryption\EncryptionAlgorithmInterface;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\KeyTransportAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\PrivateKeyAgentRSA as PrivateKeyAgentKeyTransport;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\RSA as LocalKeyTransport;
use SimpleSAML\XMLSecurity\Alg\Signature\PrivateKeyAgentRSA as PrivateKeyAgentSignature;
use SimpleSAML\XMLSecurity\Alg\Signature\RSA as LocalSignature;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Backend\EncryptionBackend;
use SimpleSAML\XMLSecurity\Backend\SignatureBackend;
use SimpleSAML\XMLSecurity\Key\AsymmetricKey;
use SimpleSAML\XMLSecurity\Key\KeyInterface;

/**
 * Registers xml-security's Private Key Agent algorithm wrappers with the algorithm factories.
 *
 * The wrappers send operations with an X509Certificate key to the agent and keep local keys on OpenSSL, so
 * the routing follows from the key type and never from a failed agent call. The registration is process-wide.
 */
final readonly class AlgorithmRegistrar
{
    /**
     * @param Closure(): SignatureBackend $signatureBackend
     * @param Closure(): EncryptionBackend $encryptionBackend
     * @param list<string> $signatureAlgorithms
     * @param list<string> $keyTransportAlgorithms
     */
    public function __construct(
        private Closure $signatureBackend,
        private Closure $encryptionBackend,
        private array $signatureAlgorithms,
        private array $keyTransportAlgorithms,
    ) {
    }

    public function register(): void
    {
        $signatureBackend = $this->signatureBackend;
        foreach ($this->signatureAlgorithms as $algorithm) {
            SignatureAlgorithmFactory::registerAlgorithmFactory(
                $algorithm,
                static fn (KeyInterface $key, string $algId): SignatureAlgorithmInterface =>
                    $key instanceof AsymmetricKey
                        ? new LocalSignature($key, $algId)
                        : new PrivateKeyAgentSignature($key, $algId, $signatureBackend()),
            );
        }

        $encryptionBackend = $this->encryptionBackend;
        foreach ($this->keyTransportAlgorithms as $algorithm) {
            KeyTransportAlgorithmFactory::registerAlgorithmFactory(
                $algorithm,
                static fn (KeyInterface $key, string $algId): EncryptionAlgorithmInterface =>
                    $key instanceof AsymmetricKey
                        ? new LocalKeyTransport($key, $algId)
                        : new PrivateKeyAgentKeyTransport($key, $algId, $encryptionBackend()),
            );
        }
    }
}
