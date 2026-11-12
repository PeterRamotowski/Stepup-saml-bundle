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

namespace Surfnet\SamlBundle\Tests\Unit\PrivateKeyAgent;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SimpleSAML\XMLSecurity\Exception\MissingTokenException;
use SimpleSAML\XMLSecurity\Exception\UnknownKeyException;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Exception\SamlInvalidConfigurationException;
use Surfnet\SamlBundle\PrivateKeyAgent\ConfiguredTokenProvider;
use Surfnet\SamlBundle\PrivateKeyAgent\KeyMap;

class KeyMapTest extends TestCase
{
    private const SIGNING_CERTIFICATE = __DIR__ . '/../../../Resources/keys/development_publickey.cer';
    private const OTHER_CERTIFICATE = __DIR__ . '/../../Component/Metadata/keys/idp-cert.pem';

    #[Test]
    public function resolves_key_names_per_operation(): void
    {
        $keyMap = new KeyMap([
            'signing' => ['certificate_file' => self::SIGNING_CERTIFICATE, 'operations' => ['sign']],
            'decryption' => ['certificate_file' => self::OTHER_CERTIFICATE, 'operations' => ['decrypt']],
        ], []);

        self::assertSame('signing', $keyMap->resolverFor('sign')->resolve($this->certificate(self::SIGNING_CERTIFICATE)));
        self::assertSame(
            'decryption',
            $keyMap->resolverFor('decrypt')->resolve($this->certificate(self::OTHER_CERTIFICATE))
        );

        $this->expectException(UnknownKeyException::class);
        $keyMap->resolverFor('sign')->resolve($this->certificate(self::OTHER_CERTIFICATE));
    }

    #[Test]
    public function accepts_a_signing_identity_with_a_signing_key(): void
    {
        $keyMap = new KeyMap(
            ['signing' => ['certificate_file' => self::SIGNING_CERTIFICATE, 'operations' => ['sign', 'decrypt']]],
            ['surfnet_saml.hosted.service_provider' => self::SIGNING_CERTIFICATE]
        );

        self::assertSame('signing', $keyMap->resolverFor('decrypt')->resolve($this->certificate(self::SIGNING_CERTIFICATE)));
    }

    #[Test]
    public function rejects_two_keys_with_the_same_certificate(): void
    {
        $this->expectException(SamlInvalidConfigurationException::class);
        $this->expectExceptionMessage('Agent keys "first" and "second" use the same certificate');

        new KeyMap([
            'first' => ['certificate_file' => self::SIGNING_CERTIFICATE, 'operations' => ['sign']],
            'second' => ['certificate_file' => self::SIGNING_CERTIFICATE, 'operations' => ['decrypt']],
        ], []);
    }

    #[Test]
    public function rejects_a_signing_identity_without_an_agent_key(): void
    {
        $this->expectException(SamlInvalidConfigurationException::class);
        $this->expectExceptionMessage('surfnet_saml.hosted.metadata uses the private key agent');

        new KeyMap(
            ['signing' => ['certificate_file' => self::SIGNING_CERTIFICATE, 'operations' => ['sign']]],
            ['surfnet_saml.hosted.metadata' => self::OTHER_CERTIFICATE]
        );
    }

    #[Test]
    public function rejects_a_signing_identity_whose_key_may_only_decrypt(): void
    {
        $this->expectException(SamlInvalidConfigurationException::class);
        $this->expectExceptionMessage('no agent key with the "sign" operation');

        new KeyMap(
            ['decryption' => ['certificate_file' => self::SIGNING_CERTIFICATE, 'operations' => ['decrypt']]],
            ['surfnet_saml.hosted.service_provider' => self::SIGNING_CERTIFICATE]
        );
    }

    #[Test]
    public function rejects_an_unreadable_certificate(): void
    {
        $this->expectException(SamlInvalidConfigurationException::class);
        $this->expectExceptionMessage('surfnet_saml.private_key_agent.keys.signing.certificate_file');

        new KeyMap(['signing' => ['certificate_file' => '/nonexistent.crt', 'operations' => ['sign']]], []);
    }

    #[Test]
    public function rejects_a_file_that_is_not_a_certificate(): void
    {
        $this->expectException(SamlInvalidConfigurationException::class);

        new KeyMap(['signing' => ['certificate_file' => __FILE__, 'operations' => ['sign']]], []);
    }

    #[Test]
    public function the_token_provider_fails_for_a_key_without_token(): void
    {
        $tokens = new ConfiguredTokenProvider(['signing' => 'secret-token', 'empty' => '']);

        self::assertSame('secret-token', $tokens->getToken('signing'));

        $this->expectException(MissingTokenException::class);
        $this->expectExceptionMessage('"empty"');
        $tokens->getToken('empty');
    }

    private function certificate(string $file): X509Certificate
    {
        return X509Certificate::fromFile($file);
    }
}
