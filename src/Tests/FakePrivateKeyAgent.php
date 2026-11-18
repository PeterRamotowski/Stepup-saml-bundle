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

namespace Surfnet\SamlBundle\Tests;

use Nyholm\Psr7\Factory\Psr17Factory;
use OpenSSLAsymmetricKey;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\KeyTransportAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Backend\PrivateKeyAgent\PrivateKeyAgentEncryptionBackend;
use SimpleSAML\XMLSecurity\Backend\PrivateKeyAgent\PrivateKeyAgentSignatureBackend;
use SimpleSAML\XMLSecurity\Constants as C;
use Surfnet\SamlBundle\DependencyInjection\PrivateKeyAgentConfiguration;
use Surfnet\SamlBundle\PrivateKeyAgent\AlgorithmRegistrar;
use Surfnet\SamlBundle\PrivateKeyAgent\ConfiguredTokenProvider;
use Surfnet\SamlBundle\PrivateKeyAgent\KeyMap;

/**
 * An in-process stand-in for the Private Key Agent's sign and decrypt endpoints, which records every request.
 *
 * Only RSA-SHA256 signatures and RSA-OAEP with SHA-1 are implemented; the real agent is exercised by the
 * target application in the workspace.
 */
final class FakePrivateKeyAgent implements ClientInterface
{
    public const string TOKEN = 'fake-agent-token';
    private const string SHA256_DIGEST_INFO = '3031300d060960864801650304020105000420';

    /**
     * @var list<string> Request paths
     */
    public array $requests = [];

    /**
     * When set, every request is answered with this status code.
     */
    public ?int $status = null;

    private readonly Psr17Factory $factory;

    /**
     * @param array<string, string> $privateKeyFiles PEM private key file by agent key name
     */
    public function __construct(private readonly array $privateKeyFiles)
    {
        $this->factory = new Psr17Factory();
    }

    /**
     * Registers the agent wrappers for the keys, as SurfnetSamlBundle::boot() does.
     */
    public function register(KeyMap $keyMap): void
    {
        $tokens = new ConfiguredTokenProvider(array_fill_keys(array_keys($this->privateKeyFiles), self::TOKEN));
        $factory = $this->factory;

        (new AlgorithmRegistrar(
            fn () => new PrivateKeyAgentSignatureBackend(
                $this,
                $factory,
                $factory,
                'https://pka.example.org',
                $tokens,
                $keyMap->resolverFor(PrivateKeyAgentConfiguration::OPERATION_SIGN)
            ),
            fn () => new PrivateKeyAgentEncryptionBackend(
                $this,
                $factory,
                $factory,
                'https://pka.example.org',
                $tokens,
                $keyMap->resolverFor(PrivateKeyAgentConfiguration::OPERATION_DECRYPT)
            ),
            [C::SIG_RSA_SHA256],
            [C::KEY_TRANSPORT_OAEP_MGF1P, C::KEY_TRANSPORT_OAEP],
        ))->register();
    }

    public static function unregister(): void
    {
        SignatureAlgorithmFactory::clearAlgorithmFactories();
        KeyTransportAlgorithmFactory::clearAlgorithmFactories();
    }

    /**
     * @return array{certificate: string, private_key: string} Files of a new self-signed RSA key pair
     */
    public static function generateKeyPair(string $directory, string $name): array
    {
        $privateKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $csr = openssl_csr_new(['commonName' => $name], $privateKey, ['digest_alg' => 'sha256']);
        $certificate = openssl_csr_sign($csr, null, $privateKey, 1, ['digest_alg' => 'sha256']);

        $files = ['certificate' => $directory . '/' . $name . '.crt', 'private_key' => $directory . '/' . $name . '.pem'];
        openssl_x509_export_to_file($certificate, $files['certificate']);
        openssl_pkey_export_to_file($privateKey, $files['private_key']);

        return $files;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $path = $request->getUri()->getPath();
        $this->requests[] = $path;

        if ($this->status !== null) {
            return $this->factory->createResponse($this->status);
        }
        if ($request->getHeaderLine('Authorization') !== 'Bearer ' . self::TOKEN) {
            return $this->factory->createResponse(401);
        }
        if (preg_match('#^/v1/(sign|decrypt)/([A-Za-z0-9_-]+)$#', $path, $matches) !== 1
            || !isset($this->privateKeyFiles[$matches[2]])
        ) {
            return $this->factory->createResponse(404);
        }

        $body = json_decode((string) $request->getBody(), true);
        $key = openssl_pkey_get_private((string) file_get_contents($this->privateKeyFiles[$matches[2]]));
        $result = $matches[1] === 'sign'
            ? $this->sign($key, $body)
            : $this->decrypt($key, $body);
        if ($result === null) {
            return $this->factory->createResponse(400);
        }

        return $this->factory->createResponse(200)->withBody($this->factory->createStream(json_encode($result)));
    }

    /**
     * @param array<string, string> $body
     * @return array<string, string>|null
     */
    private function sign(OpenSSLAsymmetricKey $key, array $body): ?array
    {
        if ($body['algorithm'] !== 'rsa-pkcs1-v1_5-sha256') {
            return null;
        }
        $digestInfo = hex2bin(self::SHA256_DIGEST_INFO) . base64_decode($body['hash'], true);
        if (!openssl_private_encrypt($digestInfo, $signature, $key, OPENSSL_PKCS1_PADDING)) {
            return null;
        }

        return ['signature' => base64_encode($signature)];
    }

    /**
     * @param array<string, string> $body
     * @return array<string, string>|null
     */
    private function decrypt(OpenSSLAsymmetricKey $key, array $body): ?array
    {
        if ($body['algorithm'] !== 'rsa-pkcs1-oaep-mgf1-sha1') {
            return null;
        }
        if (!openssl_private_decrypt((string) base64_decode($body['encrypted_data'], true), $data, $key, OPENSSL_PKCS1_OAEP_PADDING)) {
            return null;
        }

        return ['decrypted_data' => base64_encode($data)];
    }
}
