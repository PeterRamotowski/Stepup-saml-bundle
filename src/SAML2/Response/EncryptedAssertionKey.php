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

use SimpleSAML\SAML2\Assertion\Exception\InvalidAssertionException;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\XML\saml\EncryptedAssertion;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\KeyTransportAlgorithmFactory;
use SimpleSAML\XMLSecurity\XML\xenc\EncryptedKey;

/**
 * Validates the supported single-recipient layout before either backend is called.
 *
 * @internal
 */
final readonly class EncryptedAssertionKey
{
    public EncryptedKey $encryptedKey;
    public string $algorithm;
    public KeyTransportAlgorithmFactory $factory;

    public function __construct(EncryptedAssertion $encryptedAssertion)
    {
        // Only the single-recipient case is supported: xml-security 3.1.0 keeps just the first EncryptedKey of the
        // KeyInfo, saml2 ignores EncryptedKeys next to the EncryptedData, and the key transport loop would call the
        // backend once per key and abort on the first agent error. Count both places so nothing is skipped silently.
        $encryptedKeys = array_merge(
            array_values(array_filter(
                $encryptedAssertion->getEncryptedData()->getKeyInfo()?->getInfo() ?? [],
                static fn (object $info): bool => $info instanceof EncryptedKey
            )),
            $encryptedAssertion->getDecryptionKeys()
        );
        if (count($encryptedKeys) !== 1) {
            throw new InvalidAssertionException(sprintf(
                'Expected exactly one EncryptedKey in the EncryptedAssertion, found %d',
                count($encryptedKeys)
            ));
        }
        if ($encryptedAssertion->getDecryptionKeys() !== []) {
            throw new InvalidAssertionException(
                'An EncryptedKey outside the KeyInfo of the EncryptedData (RetrievalMethod layout) is not supported'
            );
        }

        $this->encryptedKey = $encryptedKeys[0];
        $algorithm = $this->encryptedKey->getEncryptionMethod()?->getAlgorithm()->getValue();
        if ($algorithm === null) {
            throw new InvalidAssertionException('The EncryptedKey has no EncryptionMethod');
        }

        $this->algorithm = $algorithm;
        $this->factory = new KeyTransportAlgorithmFactory(
            ContainerSingleton::getInstance()->getBlacklistedEncryptionAlgorithms()
                ?? KeyTransportAlgorithmFactory::DEFAULT_BLACKLIST
        );
    }
}
