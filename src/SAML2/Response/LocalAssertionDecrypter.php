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

use Exception;
use SimpleSAML\SAML2\Assertion\Exception\InvalidAssertionException;
use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\EncryptedAssertion;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;

final readonly class LocalAssertionDecrypter implements AssertionDecrypter
{
    public function __construct(private PrivateKeyLoader $privateKeyLoader)
    {
    }

    public function decrypt(
        EncryptedAssertion $encryptedAssertion,
        ServiceProvider $serviceProvider,
        IdentityProvider $identityProvider,
    ): Assertion {
        if ($serviceProvider->usesPrivateKeyAgent()) {
            throw new InvalidAssertionException('The service provider uses the private key agent, but no agent key may decrypt');
        }

        $transport = new EncryptedAssertionKey($encryptedAssertion);
        $lastException = null;
        foreach ($this->privateKeyLoader->loadDecryptionKeys($identityProvider, $serviceProvider) as $key) {
            if (!$key instanceof PrivateKey) {
                throw new InvalidAssertionException('Only RSA key transport is supported for encrypted assertions');
            }

            try {
                return $encryptedAssertion->decrypt($transport->factory->getAlgorithm($transport->algorithm, $key));
            } catch (Exception $exception) {
                $lastException = $exception;
            }
        }

        throw new InvalidAssertionException('The assertion could not be decrypted', 0, $lastException);
    }
}
