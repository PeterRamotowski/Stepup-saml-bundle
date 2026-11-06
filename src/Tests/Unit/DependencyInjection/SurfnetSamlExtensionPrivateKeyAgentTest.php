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

namespace Surfnet\SamlBundle\Tests\Unit\DependencyInjection;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SimpleSAML\XMLSecurity\Constants as C;
use Surfnet\SamlBundle\DependencyInjection\SurfnetSamlExtension;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\Argument\ServiceClosureArgument;
use Symfony\Component\DependencyInjection\Compiler\MergeExtensionConfigurationPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\RuntimeException as ContainerRuntimeException;

class SurfnetSamlExtensionPrivateKeyAgentTest extends TestCase
{
    private const CERTIFICATE = '/path/to/sp.crt';

    #[Test]
    public function without_an_agent_section_no_agent_services_are_registered(): void
    {
        $container = $this->load([$this->hosted()]);

        self::assertFalse($container->hasDefinition('surfnet_saml.private_key_agent.algorithm_registrar'));
        self::assertFalse($container->hasDefinition('surfnet_saml.private_key_agent.key_map'));
    }

    #[Test]
    public function a_disabled_agent_registers_no_agent_services(): void
    {
        $container = $this->load([$this->hosted() + ['private_key_agent' => ['enabled' => false]]]);

        self::assertFalse($container->hasDefinition('surfnet_saml.private_key_agent.algorithm_registrar'));
    }

    #[Test]
    public function an_enabled_agent_is_wired_from_the_configuration(): void
    {
        $container = $this->load([$this->hosted(useAgent: true) + ['private_key_agent' => $this->agent()]]);

        self::assertSame(
            ['sp-signing' => 'secret-token'],
            $container->getDefinition('surfnet_saml.private_key_agent.token_provider')->getArgument(0)
        );
        self::assertSame(
            [
                'timeout' => 3.0,
                'max_duration' => 5.0,
                'max_redirects' => 0,
                'verify_peer' => true,
                'verify_host' => true,
            ],
            $container->getDefinition('surfnet_saml.private_key_agent.symfony_http_client')->getArgument(0)
        );

        $keyMap = $container->getDefinition('surfnet_saml.private_key_agent.key_map');
        self::assertTrue($keyMap->isPublic());
        self::assertSame(
            ['sp-signing' => ['certificate_file' => self::CERTIFICATE, 'operations' => ['sign', 'decrypt']]],
            $keyMap->getArgument(0)
        );
        self::assertSame(['surfnet_saml.hosted.service_provider' => self::CERTIFICATE], $keyMap->getArgument(1));

        foreach (['signature_backend', 'encryption_backend'] as $backend) {
            $definition = $container->getDefinition('surfnet_saml.private_key_agent.' . $backend);
            self::assertSame('https://pka.example.org', $definition->getArgument(3));
            self::assertFalse($definition->getArgument(6));
        }

        $registrar = $container->getDefinition('surfnet_saml.private_key_agent.algorithm_registrar');
        self::assertTrue($registrar->isPublic());
        self::assertInstanceOf(ServiceClosureArgument::class, $registrar->getArgument(0));
        self::assertInstanceOf(ServiceClosureArgument::class, $registrar->getArgument(1));
        self::assertSame([C::SIG_RSA_SHA256, C::SIG_RSA_SHA384, C::SIG_RSA_SHA512], $registrar->getArgument(2));
        self::assertSame([C::KEY_TRANSPORT_OAEP_MGF1P, C::KEY_TRANSPORT_OAEP], $registrar->getArgument(3));
    }

    #[Test]
    public function an_agent_identity_gets_no_local_private_key(): void
    {
        $container = $this->load([$this->hosted(useAgent: true) + ['private_key_agent' => $this->agent()]]);

        $serviceProvider = $container->getDefinition('surfnet_saml.configuration.hosted_entities')->getArgument(2);
        self::assertTrue($serviceProvider['use_private_key_agent']);
        self::assertNull($serviceProvider['private_key']);
    }

    #[Test]
    public function the_agent_may_be_enabled_while_all_identities_keep_local_keys(): void
    {
        $container = $this->load([$this->hosted() + ['private_key_agent' => $this->agent()]]);

        self::assertSame([], $container->getDefinition('surfnet_saml.private_key_agent.key_map')->getArgument(1));
    }

    #[Test]
    public function invalid_key_names_do_not_disclose_any_bearer_token(): void
    {
        $agent = $this->agent();
        $agent['keys']['invalid.name'] = $agent['keys']['sp-signing'];
        $agent['keys']['invalid.name']['token'] = 'other-secret-token';

        try {
            $this->load([$this->hosted() + ['private_key_agent' => $agent]]);
            self::fail('An invalid key name must fail configuration loading.');
        } catch (InvalidConfigurationException $exception) {
            self::assertStringContainsString('invalid.name', $exception->getMessage());
            self::assertStringNotContainsString('secret-token', $exception->getMessage());
            self::assertStringNotContainsString('certificate_file', $exception->getMessage());
        }
    }

    #[Test]
    public function local_identities_do_not_require_sha256_in_the_agent_signature_list(): void
    {
        $agent = $this->agent();
        $agent['algorithms']['signature'] = [C::SIG_RSA_SHA512];
        $container = $this->load([$this->hosted() + ['private_key_agent' => $agent]]);

        self::assertSame([], $container->getDefinition('surfnet_saml.private_key_agent.key_map')->getArgument(1));
    }

    public static function enabledEnvironmentValues(): iterable
    {
        yield 'true' => ['true', true];
        yield 'false' => ['false', false];
        yield 'one' => ['1', true];
        yield 'zero' => ['0', false];
        yield 'on' => ['on', true];
        yield 'off' => ['off', false];
    }

    #[Test]
    #[DataProvider('enabledEnvironmentValues')]
    public function an_environment_boolean_controls_registration_through_the_extension_merge_pass(
        string $value,
        bool $enabled,
    ): void {
        $container = $this->loadWithEnabledEnvironment($value);
        self::assertSame($enabled, $container->hasDefinition('surfnet_saml.private_key_agent.algorithm_registrar'));
    }

    #[Test]
    public function an_invalid_environment_boolean_is_rejected_during_extension_merging(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('enabled must resolve to a boolean value');
        $this->loadWithEnabledEnvironment('invalid-boolean');
    }

    #[Test]
    public function symfony_rejects_casts_when_agent_enablement_is_resolved_at_compile_time(): void
    {
        $this->expectException(ContainerRuntimeException::class);
        $this->expectExceptionMessage('incompatible with resolution at compile time');
        $this->loadWithEnabledEnvironment('false', true);
    }

    private function loadWithEnabledEnvironment(string $value, bool $cast = false): ContainerBuilder
    {
        $variable = 'BUNDLE_TEST_PKA_ENABLED';
        $previous = $_ENV[$variable] ?? null;
        $_ENV[$variable] = $value;
        try {
            $container = new ContainerBuilder();
            $agent = $this->agent();
            $agent['enabled'] = '%env(' . ($cast ? 'bool:' : '') . $variable . ')%';
            $container->registerExtension(new SurfnetSamlExtension());
            $container->loadFromExtension('surfnet_saml', $this->hosted() + ['private_key_agent' => $agent]);
            (new MergeExtensionConfigurationPass())->process($container);

            return $container;
        } finally {
            if ($previous === null) {
                unset($_ENV[$variable]);
            } else {
                $_ENV[$variable] = $previous;
            }
        }
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidConfigurations(): iterable
    {
        $hosted = static fn (bool $useAgent = false, ?string $privateKey = null, ?string $publicKey = self::CERTIFICATE): array => [
            'hosted' => [
                'metadata' => ['entity_id_route' => 'metadata', 'public_key' => null, 'private_key' => null],
                'service_provider' => [
                    'enabled' => true,
                    'assertion_consumer_route' => 'acs',
                    'public_key' => $publicKey,
                    'private_key' => $privateKey,
                    'use_private_key_agent' => $useAgent,
                ],
            ],
        ];
        $agent = static fn (array $override = []): array => ['private_key_agent' => array_replace_recursive([
            'enabled' => true,
            'base_url' => 'https://pka.example.org',
            'keys' => ['sp-signing' => [
                'certificate_file' => self::CERTIFICATE,
                'token' => 'secret-token',
                'operations' => ['sign'],
            ]],
        ], $override)];

        yield 'identity uses a disabled agent' => [$hosted(true), 'requires surfnet_saml.private_key_agent.enabled'];
        yield 'identity has both a local key and the agent' => [
            $hosted(true, '/path/to/sp.key') + $agent(),
            'private_key must not be set',
        ];
        yield 'identity has no certificate' => [$hosted(true, null, null) + $agent(), 'public_key must be set'];
        yield 'missing base URL' => [$hosted() + $agent(['base_url' => null]), 'base_url must be set'];
        yield 'no keys' => [
            $hosted() + ['private_key_agent' => ['enabled' => true, 'base_url' => 'https://pka.example.org']],
            'must contain at least one key',
        ];
        yield 'invalid key name' => [
            $hosted() + $agent(['keys' => ['sp signing' => [
                'certificate_file' => self::CERTIFICATE,
                'token' => 'secret-token',
                'operations' => ['sign'],
            ]]]),
            'Agent key names must match',
        ];
        yield 'missing token' => [$hosted() + $agent(['keys' => ['sp-signing' => ['token' => '']]]), 'token'];
        yield 'unknown operation' => [
            $hosted() + $agent(['keys' => ['sp-signing' => ['operations' => ['encrypt']]]]),
            'Invalid operation',
        ];
        yield 'RSA-SHA1 signatures' => [
            $hosted() + $agent(['algorithms' => ['signature' => [C::SIG_RSA_SHA1]]]),
            'Unsupported agent signature algorithm',
        ];
        yield 'agent signing without RSA-SHA256' => [
            $hosted(true) + $agent(['algorithms' => ['signature' => [C::SIG_RSA_SHA512]]]),
            'must include RSA-SHA256',
        ];
        yield 'RSA v1.5 key transport' => [
            $hosted() + $agent(['algorithms' => ['key_transport' => [C::KEY_TRANSPORT_RSA_1_5]]]),
            'Unsupported agent key-transport algorithm',
        ];
        yield 'unbounded timeout' => [$hosted() + $agent(['max_duration' => 0]), 'max_duration'];
    }

    /**
     * @param array<string, mixed> $config
     */
    #[Test]
    #[DataProvider('invalidConfigurations')]
    public function invalid_agent_configuration_fails_while_loading(array $config, string $message): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage($message);

        $this->load([$config]);
    }

    /**
     * @param list<array<string, mixed>> $configs
     */
    private function load(array $configs): ContainerBuilder
    {
        $container = new ContainerBuilder();
        (new SurfnetSamlExtension())->load($configs, $container);

        return $container;
    }

    /**
     * @return array<string, mixed>
     */
    private function hosted(bool $useAgent = false): array
    {
        return [
            'hosted' => [
                'metadata' => ['entity_id_route' => 'metadata', 'public_key' => null, 'private_key' => null],
                'service_provider' => [
                    'enabled' => true,
                    'assertion_consumer_route' => 'acs',
                    'public_key' => self::CERTIFICATE,
                    'private_key' => $useAgent ? null : '/path/to/sp.key',
                    'use_private_key_agent' => $useAgent,
                ],
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function agent(): array
    {
        return [
            'enabled' => true,
            'base_url' => 'https://pka.example.org',
            'keys' => [
                'sp-signing' => [
                    'certificate_file' => self::CERTIFICATE,
                    'token' => 'secret-token',
                    'operations' => ['sign', 'decrypt', 'sign'],
                ],
            ],
        ];
    }
}
