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
use Surfnet\SamlBundle\Exception\SamlInvalidConfigurationException;
use Surfnet\SamlBundle\PrivateKeyAgent\KeyMap;
use Surfnet\SamlBundle\PrivateKeyAgent\ValidateKeyMapCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

class ValidateKeyMapCommandTest extends TestCase
{
    private const SIGNING_CERTIFICATE = __DIR__ . '/../../../Resources/keys/development_publickey.cer';
    private const OTHER_CERTIFICATE = __DIR__ . '/../../Component/Metadata/keys/idp-cert.pem';

    #[Test]
    public function valid_mappings_succeed(): void
    {
        $tester = new CommandTester(new ValidateKeyMapCommand(static fn (): KeyMap => new KeyMap(
            ['signing' => ['certificate_file' => self::SIGNING_CERTIFICATE, 'operations' => ['sign']]],
            ['surfnet_saml.hosted.service_provider' => self::SIGNING_CERTIFICATE]
        )));

        self::assertSame(Command::SUCCESS, $tester->execute([]));
        self::assertStringContainsString('mappings are valid', $tester->getDisplay());
    }

    #[Test]
    public function an_identity_without_a_signing_key_fails(): void
    {
        $tester = new CommandTester(new ValidateKeyMapCommand(static fn (): KeyMap => new KeyMap(
            ['signing' => ['certificate_file' => self::SIGNING_CERTIFICATE, 'operations' => ['sign']]],
            ['surfnet_saml.hosted.metadata' => self::OTHER_CERTIFICATE]
        )));

        $this->expectException(SamlInvalidConfigurationException::class);
        $this->expectExceptionMessage('surfnet_saml.hosted.metadata uses the private key agent');
        $tester->execute([]);
    }
}
