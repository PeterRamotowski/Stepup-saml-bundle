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

use RuntimeException;
use SimpleSAML\XMLSecurity\Backend\PrivateKeyAgent\FingerprintKeyNameResolver;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;
use Surfnet\SamlBundle\Exception\SamlInvalidConfigurationException;

/**
 * Maps the SHA-256 fingerprints of the configured agent certificates to agent key names, per operation.
 *
 * Construction reads the certificates and fails when two keys share a certificate or when a hosted identity
 * that uses the agent has no signing key.
 */
final class KeyMap
{
    /**
     * @var array<string, array<string, string>> Key name by fingerprint, per operation
     */
    private array $keyNames = [
        AgentOperation::SIGN => [],
        AgentOperation::DECRYPT => [],
    ];

    /**
     * @var array<string, list<X509Certificate>> In configuration order, per operation
     */
    private array $certificates = [
        AgentOperation::SIGN => [],
        AgentOperation::DECRYPT => [],
    ];

    /**
     * @param array<string, array{certificate_file: string, operations: list<string>}> $keys By agent key name
     * @param array<string, string> $signingIdentities Certificate file by configuration path of the identity
     */
    public function __construct(array $keys, array $signingIdentities)
    {
        $keyNameByFingerprint = [];
        foreach ($keys as $keyName => $key) {
            $keyName = (string) $keyName;
            $certificate = self::certificate(
                $key['certificate_file'],
                sprintf('surfnet_saml.private_key_agent.keys.%s.certificate_file', $keyName)
            );
            $fingerprint = self::fingerprintOf($certificate);
            if (isset($keyNameByFingerprint[$fingerprint])) {
                throw new SamlInvalidConfigurationException(sprintf(
                    'Agent keys "%s" and "%s" use the same certificate (SHA-256 fingerprint %s).',
                    $keyNameByFingerprint[$fingerprint],
                    $keyName,
                    $fingerprint
                ));
            }
            $keyNameByFingerprint[$fingerprint] = $keyName;

            foreach ($key['operations'] as $operation) {
                $this->keyNames[$operation][$fingerprint] = $keyName;
                $this->certificates[$operation][] = $certificate;
            }
        }

        foreach ($signingIdentities as $path => $certificateFile) {
            $fingerprint = self::fingerprintOf(self::certificate($certificateFile, $path . '.public_key'));
            if (!isset($this->keyNames[AgentOperation::SIGN][$fingerprint])) {
                throw new SamlInvalidConfigurationException(sprintf(
                    '%s uses the private key agent, but no agent key with the "sign" operation has its '
                    . 'certificate (SHA-256 fingerprint %s).',
                    $path,
                    $fingerprint
                ));
            }
        }
    }

    public function resolverFor(string $operation): FingerprintKeyNameResolver
    {
        if (!array_key_exists($operation, $this->keyNames)) {
            throw new InvalidArgumentException(sprintf('Unknown agent operation "%s"', $operation));
        }

        return new FingerprintKeyNameResolver($this->keyNames[$operation]);
    }

    /**
     * The certificates of the agent keys that may perform the operation, in configuration order.
     *
     * @return list<X509Certificate>
     */
    public function certificatesFor(string $operation): array
    {
        if (!array_key_exists($operation, $this->certificates)) {
            throw new InvalidArgumentException(sprintf('Unknown agent operation "%s"', $operation));
        }

        return $this->certificates[$operation];
    }

    public static function fingerprintOf(X509Certificate $certificate): string
    {
        return strtolower($certificate->getRawThumbprint(C::DIGEST_SHA256));
    }

    private static function certificate(string $certificateFile, string $path): X509Certificate
    {
        try {
            return X509Certificate::fromFile($certificateFile);
        } catch (RuntimeException $exception) {
            throw new SamlInvalidConfigurationException(
                sprintf('%s: could not read a PEM certificate from "%s".', $path, $certificateFile),
                0,
                $exception
            );
        }
    }
}
