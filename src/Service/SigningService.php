<?php

/**
 * Copyright 2014 SURFnet bv
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

namespace Surfnet\SamlBundle\Service;

use SimpleSAML\SAML2\Certificate\KeyLoader as PublicKeyLoader;
use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\Certificate\X509;
use SimpleSAML\SAML2\Configuration\PrivateKey as PrivateKeyFile;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\Signing\CertificateKeys;
use Surfnet\SamlBundle\Signing\DomElementSigner;
use Surfnet\SamlBundle\Signing\KeyPair;
use Surfnet\SamlBundle\Signing\Signable;
use Surfnet\SamlBundle\Signing\SignatureAlgorithms;

class SigningService
{
    public function __construct(
        private readonly PublicKeyLoader $publicKeyLoader,
        private readonly PrivateKeyLoader $privateKeyLoader
    ) {
    }

    public function sign(Signable $signable, KeyPair $keyPair): Signable
    {
        $publicKey = $this->loadPublicKeyFromFile($keyPair->publicKeyFile);
        $privateKey = $this->loadPrivateKeyFromFile($keyPair->privateKeyFile);

        $signer = SignatureAlgorithms::factory()->getAlgorithm(C::SIG_RSA_SHA256, $privateKey);

        DomElementSigner::signEnveloped(
            $signable->getRootDomElement(),
            $signer,
            CertificateKeys::toKeyInfo($publicKey),
            $signable->getAppendBeforeNode()
        );

        return $signable;
    }

    /**
     * @param string $publicKeyFile /full/path/to/the/public/key
     */
    public function loadPublicKeyFromFile(string $publicKeyFile): X509
    {
        $this->publicKeyLoader->loadCertificateData(CertificateKeys::certificateDataFromFile($publicKeyFile));
        $keyCollection = $this->publicKeyLoader->getKeys();
        $publicKey = $keyCollection->getOnlyElement();
        if (!$publicKey instanceof X509) {
            throw new RuntimeException(sprintf('Could not load a certificate from "%s"', $publicKeyFile));
        }

        // remove it from the collection so we can reuse the publicKeyLoader for consecutive signing
        $keyCollection->remove($publicKey);

        return $publicKey;
    }

    /**
     * @param string $privateKeyFile /full/path/to/the/private/key
     * @return PrivateKey
     */
    public function loadPrivateKeyFromFile(string $privateKeyFile): PrivateKey
    {
        $privateKey = new PrivateKeyFile($privateKeyFile, 'metadata');
        return $this->privateKeyLoader->loadPrivateKey($privateKey);
    }
}
