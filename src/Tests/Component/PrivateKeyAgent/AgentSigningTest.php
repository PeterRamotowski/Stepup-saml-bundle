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

namespace Surfnet\SamlBundle\Tests\Component\PrivateKeyAgent;

use Closure;
use Mockery as m;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Configuration\PrivateKey as PrivateKeyConfiguration;
use SimpleSAML\SAML2\XML\md\EntityDescriptor;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\RSA;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Exception\AgentUnavailableException;
use SimpleSAML\XMLSecurity\Exception\UnsupportedAlgorithmException;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\Metadata\MetadataConfiguration;
use Surfnet\SamlBundle\Metadata\MetadataFactory;
use Surfnet\SamlBundle\PrivateKeyAgent\KeyMap;
use Surfnet\SamlBundle\SAML2\AuthnRequestFactory;
use Surfnet\SamlBundle\SAML2\BridgeContainer;
use Surfnet\SamlBundle\Service\SigningService;
use Surfnet\SamlBundle\Signing\KeyPair;
use Surfnet\SamlBundle\Signing\Signers;
use Surfnet\SamlBundle\Tests\FakePrivateKeyAgent;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Routing\RouterInterface;
use Twig\Environment;
use Twig\Loader\ArrayLoader;

/**
 * AuthnRequest, metadata and hosted IdP signatures of agent identities go to the agent, once per signature.
 */
class AgentSigningTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private const string KEYS = __DIR__ . '/../../../Resources/keys';
    private const string CERTIFICATE = self::KEYS . '/development_publickey.cer';

    private FakePrivateKeyAgent $agent;

    protected function setUp(): void
    {
        ContainerSingleton::setContainer(new BridgeContainer(new NullLogger(), new MockClock('2026-11-04T12:00:00Z')));

        $this->agent = new FakePrivateKeyAgent(['sp-signing' => self::KEYS . '/development_privatekey.pem']);
        $this->agent->register(new KeyMap(
            ['sp-signing' => ['certificate_file' => self::CERTIFICATE, 'operations' => ['sign']]],
            []
        ));
    }

    protected function tearDown(): void
    {
        FakePrivateKeyAgent::unregister();
    }

    #[Test]
    public function an_authn_request_of_an_agent_service_provider_is_signed_by_the_agent(): void
    {
        $query = AuthnRequestFactory::createNewRequest($this->serviceProvider(true), $this->identityProvider())
            ->buildRequestQuery();

        [$signedPart, $signature] = explode('&Signature=', $query);
        self::assertTrue($this->verify($signedPart, base64_decode(urldecode($signature), true)));
        self::assertSame(['/v1/sign/sp-signing'], $this->agent->requests);
    }

    #[Test]
    public function an_authn_request_of_a_local_service_provider_never_calls_the_agent(): void
    {
        $query = AuthnRequestFactory::createNewRequest($this->serviceProvider(false), $this->identityProvider())
            ->buildRequestQuery();

        [$signedPart, $signature] = explode('&Signature=', $query);
        self::assertTrue($this->verify($signedPart, base64_decode(urldecode($signature), true)));
        self::assertSame([], $this->agent->requests);
    }

    #[Test]
    public function an_unavailable_agent_fails_the_authn_request_after_one_call(): void
    {
        $this->agent->status = 503;
        $authnRequest = AuthnRequestFactory::createNewRequest($this->serviceProvider(true), $this->identityProvider());

        try {
            $authnRequest->buildRequestQuery();
            self::fail('An unavailable agent must fail the signature.');
        } catch (AgentUnavailableException $exception) {
            self::assertStringNotContainsString(FakePrivateKeyAgent::TOKEN, (string) $exception);
        }

        self::assertSame(['/v1/sign/sp-signing'], $this->agent->requests);
    }

    #[Test]
    public function metadata_of_an_agent_identity_is_signed_by_the_agent_without_reading_a_private_key(): void
    {
        $configuration = new MetadataConfiguration();
        $configuration->entityIdRoute = 'metadata';
        $configuration->isSp = true;
        $configuration->assertionConsumerRoute = 'acs';
        $configuration->publicKey = self::CERTIFICATE;
        $configuration->privateKey = '/nonexistent/private-key.pem';
        $configuration->usePrivateKeyAgent = true;

        $twig = new Environment(new ArrayLoader([
            '@SurfnetSaml/Metadata/metadata.xml.twig' => file_get_contents(dirname(__DIR__, 4) . '/templates/Metadata/metadata.xml.twig'),
        ]));
        $router = m::mock(RouterInterface::class);
        $router->shouldReceive('generate')->andReturn('https://sp.example.com/metadata');
        $metadata = (new MetadataFactory($twig, $router, new SigningService(new KeyLoader(), new PrivateKeyLoader()), $configuration))
            ->generate();

        $entityDescriptor = EntityDescriptor::fromXML(DOMDocumentFactory::fromString((string) $metadata)->documentElement);
        $verifier = (new SignatureAlgorithmFactory())->getAlgorithm(
            C::SIG_RSA_SHA256,
            X509Certificate::fromFile(self::CERTIFICATE)->getPublicKey()
        );
        self::assertInstanceOf(EntityDescriptor::class, $entityDescriptor->verify($verifier));
        self::assertSame(['/v1/sign/sp-signing'], $this->agent->requests);
    }

    #[Test]
    public function a_hosted_identity_provider_gets_an_agent_signer(): void
    {
        $identityProvider = new IdentityProvider([
            'entityId' => 'https://idp.example.com/metadata',
            'certificateFile' => self::CERTIFICATE,
            'privateKeys' => [],
            'privateKeyAgent' => true,
        ]);

        $signature = Signers::forHostedEntity($identityProvider)->sign('response');

        self::assertTrue($this->verify('response', $signature));
        self::assertSame(['/v1/sign/sp-signing'], $this->agent->requests);
    }

    #[Test]
    public function an_agent_identity_cannot_sign_when_the_agent_is_not_registered(): void
    {
        FakePrivateKeyAgent::unregister();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(sprintf('The private key agent is not registered for "%s" signatures', C::SIG_RSA_SHA256));

        Signers::forHostedEntity($this->serviceProvider(true));
    }

    /**
     * @return iterable<string, array{Closure(string): SignatureAlgorithmInterface, bool}> Creates a signer for an algorithm; whether it uses the agent
     */
    public static function signerEntryPoints(): iterable
    {
        $keyPair = static function (bool $useAgent): KeyPair {
            $keyPair = new KeyPair();
            $keyPair->publicKeyFile = self::CERTIFICATE;
            $keyPair->privateKeyFile = $useAgent ? '/nonexistent/private-key.pem' : self::KEYS . '/development_privatekey.pem';
            $keyPair->usePrivateKeyAgent = $useAgent;

            return $keyPair;
        };
        $hostedEntity = static fn (bool $useAgent): IdentityProvider => new IdentityProvider([
            'entityId' => 'https://idp.example.com/metadata',
            'certificateFile' => self::CERTIFICATE,
            'privateKeys' => $useAgent
                ? []
                : [new PrivateKeyConfiguration(self::KEYS . '/development_privatekey.pem', PrivateKeyConfiguration::NAME_DEFAULT)],
            'privateKeyAgent' => $useAgent,
        ]);

        yield 'agent hosted entity' => [static fn (string $algorithm): SignatureAlgorithmInterface => Signers::forHostedEntity($hostedEntity(true), $algorithm), true];
        yield 'local hosted entity' => [static fn (string $algorithm): SignatureAlgorithmInterface => Signers::forHostedEntity($hostedEntity(false), $algorithm), false];
        yield 'agent key pair' => [static fn (string $algorithm): SignatureAlgorithmInterface => Signers::forKeyPair($keyPair(true), null, $algorithm), true];
        yield 'local key pair' => [static fn (string $algorithm): SignatureAlgorithmInterface => Signers::forKeyPair($keyPair(false), null, $algorithm), false];
        yield 'private key' => [
            static fn (string $algorithm): SignatureAlgorithmInterface => Signers::forPrivateKey(
                new PrivateKeyConfiguration(self::KEYS . '/development_privatekey.pem', PrivateKeyConfiguration::NAME_DEFAULT),
                null,
                $algorithm
            ),
            false,
        ];
        yield 'local key' => [
            static fn (string $algorithm): SignatureAlgorithmInterface => Signers::forLocalKey(PrivateKey::fromFile(self::KEYS . '/development_privatekey.pem'), $algorithm),
            false,
        ];
        yield 'agent certificate' => [static fn (string $algorithm): SignatureAlgorithmInterface => Signers::forAgentCertificate(self::CERTIFICATE, $algorithm), true];
    }

    #[Test]
    #[DataProvider('signerEntryPoints')]
    public function every_entry_point_signs_with_the_requested_rsa_sha2_algorithm(Closure $createSigner, bool $usesAgent): void
    {
        foreach ([C::SIG_RSA_SHA384, C::SIG_RSA_SHA512] as $algorithm) {
            $signer = $createSigner($algorithm);

            self::assertSame($algorithm, $signer->getAlgorithmId());
            self::assertTrue($this->verify('data', $signer->sign('data'), $algorithm));
        }

        self::assertSame($usesAgent ? ['/v1/sign/sp-signing', '/v1/sign/sp-signing'] : [], $this->agent->requests);
    }

    #[Test]
    #[DataProvider('signerEntryPoints')]
    public function every_entry_point_rejects_unsupported_and_blacklisted_algorithms(Closure $createSigner): void
    {
        ContainerSingleton::getInstance()->setBlacklistedAlgorithms([C::SIG_RSA_SHA384]);

        foreach ([C::SIG_RSA_SHA1, C::SIG_RSA_PSS_SHA256, C::SIG_HMAC_SHA256, C::SIG_RSA_SHA384] as $algorithm) {
            self::assertFalse(Signers::supports($algorithm));
            try {
                $createSigner($algorithm);
                self::fail(sprintf('"%s" must not produce a signer.', $algorithm));
            } catch (UnsupportedAlgorithmException $exception) {
                self::assertStringContainsString($algorithm, $exception->getMessage());
            }
        }

        self::assertTrue(Signers::supports(C::SIG_RSA_SHA512));
        self::assertSame([], $this->agent->requests);
    }

    #[Test]
    public function an_agent_identity_names_an_algorithm_the_agent_is_not_registered_for(): void
    {
        FakePrivateKeyAgent::unregister();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(sprintf('The private key agent is not registered for "%s" signatures', C::SIG_RSA_SHA512));

        Signers::forAgentCertificate(self::CERTIFICATE, C::SIG_RSA_SHA512);
    }

    public static function agentIdentitiesWithoutCertificate(): iterable
    {
        yield 'hosted entity' => [
            static fn () => Signers::forHostedEntity(new IdentityProvider([
                'entityId' => 'https://idp.example.com/metadata',
                'privateKeys' => [],
                'privateKeyAgent' => true,
            ])),
            'The hosted entity "https://idp.example.com/metadata" uses the private key agent but has no certificate file',
        ];
        yield 'metadata key pair' => [
            static function () {
                $keyPair = new KeyPair();
                $keyPair->publicKeyFile = '';
                $keyPair->usePrivateKeyAgent = true;

                return Signers::forKeyPair($keyPair);
            },
            'The metadata signing key pair uses the private key agent but has no certificate file',
        ];
    }

    #[Test]
    #[DataProvider('agentIdentitiesWithoutCertificate')]
    public function an_agent_identity_without_a_certificate_is_named_in_the_error(Closure $createSigner, string $message): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage($message);

        $createSigner();
    }

    private function serviceProvider(bool $useAgent): ServiceProvider
    {
        return new ServiceProvider([
            'entityId' => 'https://sp.example.com/metadata',
            'assertionConsumerUrl' => 'https://sp.example.com/acs',
            'certificateFile' => self::CERTIFICATE,
            'privateKeys' => $useAgent
                ? []
                : [new PrivateKeyConfiguration(self::KEYS . '/development_privatekey.pem', PrivateKeyConfiguration::NAME_DEFAULT)],
            'privateKeyAgent' => $useAgent,
        ]);
    }

    private function identityProvider(): IdentityProvider
    {
        return new IdentityProvider([
            'entityId' => 'https://idp.example.com/metadata',
            'ssoUrl' => 'https://idp.example.com/sso',
            'certificateFile' => self::CERTIFICATE,
        ]);
    }

    private function verify(string $data, string|false $signature, string $algorithm = C::SIG_RSA_SHA256): bool
    {
        return $signature !== false
            && (new RSA(X509Certificate::fromFile(self::CERTIFICATE)->getPublicKey(), $algorithm))->verify($data, $signature);
    }
}
