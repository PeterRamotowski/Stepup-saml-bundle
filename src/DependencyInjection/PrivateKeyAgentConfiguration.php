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

namespace Surfnet\SamlBundle\DependencyInjection;

use SimpleSAML\XMLSecurity\Backend\PrivateKeyAgent\KeyNameResolver;
use SimpleSAML\XMLSecurity\Constants as C;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * The optional surfnet_saml.private_key_agent section.
 *
 * SurfnetSamlExtension processes this section on its own, because the rest of the bundle configuration is
 * merged without the configuration tree.
 */
final class PrivateKeyAgentConfiguration implements ConfigurationInterface
{
    public const string OPERATION_SIGN = 'sign';
    public const string OPERATION_DECRYPT = 'decrypt';

    public const array SUPPORTED_SIGNATURE_ALGORITHMS = [
        C::SIG_RSA_SHA256,
        C::SIG_RSA_SHA384,
        C::SIG_RSA_SHA512,
    ];

    public const array SUPPORTED_KEY_TRANSPORT_ALGORITHMS = [
        C::KEY_TRANSPORT_OAEP_MGF1P,
        C::KEY_TRANSPORT_OAEP,
    ];

    /**
     * @SuppressWarnings("PHPMD.ExcessiveMethodLength")
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('private_key_agent');

        $treeBuilder->getRootNode()
            ->info('Optional Private Key Agent for RSA signing and key-transport decryption')
            ->canBeEnabled()
            ->validate()
                ->ifTrue(static fn (array $config): bool => $config['enabled'] && empty($config['base_url']))
                ->thenInvalid('surfnet_saml.private_key_agent.base_url must be set when the agent is enabled')
            ->end()
            ->validate()
                ->ifTrue(static fn (array $config): bool => $config['enabled'] && $config['keys'] === [])
                ->thenInvalid('surfnet_saml.private_key_agent.keys must contain at least one key when the agent is enabled')
            ->end()
            ->children()
                ->scalarNode('base_url')
                    ->defaultNull()
                    ->info('Base URL of the agent; must use https://, unless allow_insecure_http is set for a loopback host')
                ->end()
                ->booleanNode('allow_insecure_http')
                    ->defaultFalse()
                    ->info('Permit http:// for a loopback agent (localhost, 127.0.0.0/8, ::1) only')
                ->end()
                ->floatNode('timeout')
                    ->defaultValue(3.0)
                    ->min(0.1)
                    ->max(30.0)
                    ->info('Idle timeout in seconds for an agent request')
                ->end()
                ->floatNode('max_duration')
                    ->defaultValue(5.0)
                    ->min(0.1)
                    ->max(60.0)
                    ->info('Maximum total duration in seconds of an agent request')
                ->end()
                ->arrayNode('keys')
                    ->info('Agent keys by key name, each identified by the SHA-256 fingerprint of its certificate')
                    ->useAttributeAsKey('name')
                    // Key names are agent identifiers; keep dashes instead of normalising them to underscores.
                    ->normalizeKeys(false)
                    ->arrayPrototype()
                        ->children()
                            ->scalarNode('certificate_file')
                                ->isRequired()
                                ->cannotBeEmpty()
                                ->info('The PEM certificate whose public key belongs to this agent key')
                            ->end()
                            ->scalarNode('token')
                                ->isRequired()
                                ->cannotBeEmpty()
                                ->info('Bearer token for this key; read it from a secret, e.g. %env(trim:file:PKA_TOKEN_FILE)%')
                            ->end()
                            ->arrayNode('operations')
                                ->info('Operations this application may request with the key')
                                ->isRequired()
                                ->requiresAtLeastOneElement()
                                ->scalarPrototype()
                                    ->validate()
                                        ->ifNotInArray([self::OPERATION_SIGN, self::OPERATION_DECRYPT])
                                        ->thenInvalid('Invalid operation %s; use "sign" or "decrypt"')
                                    ->end()
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                    ->validate()
                        ->ifTrue(static fn (array $keys): bool => array_any(
                            array_keys($keys),
                            static fn (int|string $name): bool =>
                                preg_match(KeyNameResolver::KEY_NAME_PATTERN, (string) $name) !== 1
                        ))
                        ->thenInvalid('Agent key names must match [a-zA-Z0-9_-]{1,64}: %s')
                    ->end()
                ->end()
                ->arrayNode('algorithms')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->arrayNode('signature')
                            ->info('Signature algorithms routed to the agent for certificate identities')
                            ->requiresAtLeastOneElement()
                            ->defaultValue(self::SUPPORTED_SIGNATURE_ALGORITHMS)
                            ->scalarPrototype()
                                ->validate()
                                    ->ifNotInArray(self::SUPPORTED_SIGNATURE_ALGORITHMS)
                                    ->thenInvalid('Unsupported agent signature algorithm %s')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('key_transport')
                            ->info('RSA key-transport algorithms routed to the agent for certificate identities')
                            ->requiresAtLeastOneElement()
                            ->defaultValue(self::SUPPORTED_KEY_TRANSPORT_ALGORITHMS)
                            ->scalarPrototype()
                                ->validate()
                                    ->ifNotInArray(self::SUPPORTED_KEY_TRANSPORT_ALGORITHMS)
                                    ->thenInvalid('Unsupported agent key-transport algorithm %s')
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
