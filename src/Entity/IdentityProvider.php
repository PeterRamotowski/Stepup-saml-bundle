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

namespace Surfnet\SamlBundle\Entity;

use SimpleSAML\SAML2\Configuration\CertificateProvider;
use SimpleSAML\SAML2\Configuration\DecryptionProvider;
use SimpleSAML\SAML2\Configuration\EntityIdProvider;
use SimpleSAML\SAML2\Configuration\IdentityProvider as IdentityProviderConfiguration;
use SimpleSAML\SAML2\Configuration\Queryable;

/**
 * saml2 v7 declares its IdentityProvider configuration final, so this entity wraps it instead of extending it.
 */
class IdentityProvider implements CertificateProvider, DecryptionProvider, EntityIdProvider, Queryable
{
    private readonly IdentityProviderConfiguration $configuration;

    public function __construct(array $configuration)
    {
        $this->configuration = new IdentityProviderConfiguration($configuration);
    }

    public function getConfiguration(): IdentityProviderConfiguration
    {
        return $this->configuration;
    }

    public function getSsoUrl()
    {
        return $this->get('ssoUrl');
    }

    public function get(string $key, $defaultValue = null)
    {
        return $this->configuration->get($key, $defaultValue);
    }

    public function has(string $key): bool
    {
        return $this->configuration->has($key);
    }

    public function getKeys()
    {
        return $this->configuration->getKeys();
    }

    public function getCertificateData(): ?string
    {
        return $this->configuration->getCertificateData();
    }

    public function getCertificateFile(): ?string
    {
        return $this->configuration->getCertificateFile();
    }

    public function getCertificateFingerprints()
    {
        return $this->configuration->getCertificateFingerprints();
    }

    public function isAssertionEncryptionRequired(): ?bool
    {
        return $this->configuration->isAssertionEncryptionRequired();
    }

    public function getSharedKey(): ?string
    {
        return $this->configuration->getSharedKey();
    }

    public function getPrivateKey(string $name, ?bool $required = null)
    {
        return $this->configuration->getPrivateKey($name, $required);
    }

    public function getBlacklistedAlgorithms(): ?array
    {
        return $this->configuration->getBlacklistedAlgorithms();
    }

    public function getEntityId(): ?string
    {
        return $this->configuration->getEntityId();
    }
}
