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

use ArrayObject;
use LogicException;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\KeyTransportAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\PrivateKeyAgentRSA as PrivateKeyAgentKeyTransport;
use SimpleSAML\XMLSecurity\Alg\Signature\PrivateKeyAgentRSA as PrivateKeyAgentSignature;
use SimpleSAML\XMLSecurity\Alg\Signature\RSA;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Backend\PrivateKeyAgent\PrivateKeyAgentEncryptionBackend;
use SimpleSAML\XMLSecurity\Backend\PrivateKeyAgent\PrivateKeyAgentSignatureBackend;
use SimpleSAML\XMLSecurity\Backend\PrivateKeyAgent\StaticKeyNameResolver;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Exception\AgentUnavailableException;
use SimpleSAML\XMLSecurity\Exception\BlacklistedAlgorithmException;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\PrivateKeyAgent\AlgorithmRegistrar;
use Surfnet\SamlBundle\PrivateKeyAgent\ConfiguredTokenProvider;

class AlgorithmRegistrarTest extends TestCase
{
    private const KEYS = __DIR__ . '/../../../Resources/keys';

    /**
     * @var ArrayObject<int, RequestInterface>
     */
    private ArrayObject $agentRequests;

    protected function setUp(): void
    {
        $factory = new Psr17Factory();
        $this->agentRequests = new ArrayObject();
        $client = new class ($factory, $this->agentRequests) implements ClientInterface {
            /**
             * @param ArrayObject<int, RequestInterface> $requests
             */
            public function __construct(private readonly Psr17Factory $factory, private readonly ArrayObject $requests)
            {
            }

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                $this->requests->append($request);

                return $this->factory->createResponse(503);
            }
        };
        $tokens = new ConfiguredTokenProvider(['test-key' => 'secret-token']);
        $resolver = new StaticKeyNameResolver('test-key');

        (new AlgorithmRegistrar(
            static fn () => new PrivateKeyAgentSignatureBackend(
                $client,
                $factory,
                $factory,
                'https://pka.example.org',
                $tokens,
                $resolver
            ),
            static fn () => new PrivateKeyAgentEncryptionBackend(
                $client,
                $factory,
                $factory,
                'https://pka.example.org',
                $tokens,
                $resolver
            ),
            [C::SIG_RSA_SHA256],
            [C::KEY_TRANSPORT_OAEP_MGF1P],
        ))->register();
    }

    protected function tearDown(): void
    {
        SignatureAlgorithmFactory::clearAlgorithmFactories();
        KeyTransportAlgorithmFactory::clearAlgorithmFactories();
    }

    #[Test]
    public function certificate_identities_get_the_agent_wrappers(): void
    {
        self::assertInstanceOf(
            PrivateKeyAgentSignature::class,
            (new SignatureAlgorithmFactory())->getAlgorithm(C::SIG_RSA_SHA256, $this->certificate())
        );
        self::assertInstanceOf(
            PrivateKeyAgentKeyTransport::class,
            (new KeyTransportAlgorithmFactory())->getAlgorithm(C::KEY_TRANSPORT_OAEP_MGF1P, $this->certificate())
        );
    }

    #[Test]
    public function local_keys_still_sign_locally(): void
    {
        $signature = (new SignatureAlgorithmFactory())
            ->getAlgorithm(C::SIG_RSA_SHA256, PrivateKey::fromFile(self::KEYS . '/development_privatekey.pem'))
            ->sign('data');

        self::assertTrue(
            (new RSA($this->certificate()->getPublicKey(), C::SIG_RSA_SHA256))->verify('data', $signature)
        );
        self::assertCount(0, $this->agentRequests);
    }

    #[Test]
    public function an_agent_failure_is_not_replaced_by_a_local_signature(): void
    {
        $signer = (new SignatureAlgorithmFactory())->getAlgorithm(C::SIG_RSA_SHA256, $this->certificate());

        try {
            $signer->sign('data');
            self::fail('An unavailable agent must fail the signature.');
        } catch (AgentUnavailableException) {
        }

        self::assertCount(1, $this->agentRequests);
        self::assertSame('Bearer secret-token', $this->agentRequests[0]->getHeaderLine('Authorization'));
    }

    #[Test]
    public function the_factory_blacklist_still_applies(): void
    {
        $this->expectException(BlacklistedAlgorithmException::class);

        (new SignatureAlgorithmFactory([C::SIG_RSA_SHA256]))->getAlgorithm(C::SIG_RSA_SHA256, $this->certificate());
    }

    #[Test]
    public function local_crypto_works_even_when_agent_backend_construction_fails(): void
    {
        $unavailable = static function (): never {
            throw new LogicException('The agent backend cannot be constructed');
        };
        (new AlgorithmRegistrar($unavailable, $unavailable, [C::SIG_RSA_SHA256], [C::KEY_TRANSPORT_OAEP_MGF1P]))->register();
        $privateKey = PrivateKey::fromFile(self::KEYS . '/development_privatekey.pem');
        $publicKey = $this->certificate()->getPublicKey();
        $signatures = new SignatureAlgorithmFactory();
        $signature = $signatures->getAlgorithm(C::SIG_RSA_SHA256, $privateKey)->sign('local data');
        self::assertTrue($signatures->getAlgorithm(C::SIG_RSA_SHA256, $publicKey)->verify('local data', $signature));

        $transport = new KeyTransportAlgorithmFactory();
        $ciphertext = $transport->getAlgorithm(C::KEY_TRANSPORT_OAEP_MGF1P, $publicKey)->encrypt('session key');
        self::assertSame('session key', $transport->getAlgorithm(C::KEY_TRANSPORT_OAEP_MGF1P, $privateKey)->decrypt($ciphertext));
        self::assertCount(0, $this->agentRequests);
    }

    private function certificate(): X509Certificate
    {
        return X509Certificate::fromFile(self::KEYS . '/development_publickey.cer');
    }
}
