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

use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\Configuration\PrivateKey;
use SimpleSAML\XMLSecurity\Alg\Signature\PrivateKeyAgentRSA;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Key\PrivateKey as LocalPrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Exception\RuntimeException;
use TypeError;

/**
 * RSA-SHA256 signers for hosted entities: the private key agent for an agent identity, its local key otherwise.
 *
 * An agent identity never reads a private key file, so an agent failure cannot turn into a local signature.
 */
final class Signers
{
    public static function forHostedEntity(ServiceProvider|IdentityProvider $entity): SignatureAlgorithmInterface
    {
        if ($entity->usesPrivateKeyAgent()) {
            $certificateFile = $entity->getCertificateFile();
            if (!is_string($certificateFile) || $certificateFile === '') {
                throw new RuntimeException(sprintf(
                    'The hosted entity "%s" uses the private key agent but has no certificate file',
                    (string) $entity->getEntityId()
                ));
            }

            return self::forAgentCertificate($certificateFile);
        }

        $privateKey = $entity->getPrivateKey(PrivateKey::NAME_DEFAULT);
        if (!$privateKey instanceof PrivateKey) {
            throw new RuntimeException(sprintf(
                'The hosted entity "%s" has no default private key configured',
                (string) $entity->getEntityId()
            ));
        }

        return self::forPrivateKey($privateKey);
    }

    public static function forPrivateKey(PrivateKey $privateKey): SignatureAlgorithmInterface
    {
        return self::forLocalKey((new PrivateKeyLoader())->loadPrivateKey($privateKey));
    }

    public static function forLocalKey(LocalPrivateKey $privateKey): SignatureAlgorithmInterface
    {
        return SignatureAlgorithms::factory()->getAlgorithm(C::SIG_RSA_SHA256, $privateKey);
    }

    /**
     * A signer that sends the signature operation for the certificate's key to the private key agent.
     */
    public static function forAgentCertificate(string $certificateFile): SignatureAlgorithmInterface
    {
        $certificate = X509Certificate::fromFile($certificateFile);

        try {
            $signer = SignatureAlgorithms::factory()->getAlgorithm(C::SIG_RSA_SHA256, $certificate);
        } catch (TypeError $exception) {
            // The default RSA class only accepts key material, so this means no agent wrapper is registered.
            throw new RuntimeException('The private key agent is not registered for RSA-SHA256 signatures', 0, $exception);
        }

        if (!$signer instanceof PrivateKeyAgentRSA) {
            throw new RuntimeException('The private key agent is not registered for RSA-SHA256 signatures');
        }

        return $signer;
    }
}
