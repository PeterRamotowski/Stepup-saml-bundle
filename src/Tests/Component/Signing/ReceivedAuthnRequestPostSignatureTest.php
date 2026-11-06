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

namespace Surfnet\SamlBundle\Tests\Component\Signing;

use Exception;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Compat\MockContainer;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\Type\SAMLDateTimeValue;
use SimpleSAML\SAML2\Type\SAMLStringValue;
use SimpleSAML\SAML2\XML\saml\Issuer;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SAML2AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\Extensions as SAML2Extensions;
use SimpleSAML\XML\Chunk;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSchema\Type\IDValue;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\PublicKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Entity\ServiceProviderRepository;
use Surfnet\SamlBundle\Http\Exception\SignatureValidationFailedException;
use Surfnet\SamlBundle\Http\PostBinding;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestPost;
use Surfnet\SamlBundle\SAML2\ReceivedAuthnRequest;
use Surfnet\SamlBundle\SAML2\Response\ResponseProcessor;
use Surfnet\SamlBundle\Signing\CertificateKeys;
use Surfnet\SamlBundle\Signing\SignatureVerifier;
use Symfony\Component\HttpFoundation\Request;

class ReceivedAuthnRequestPostSignatureTest extends TestCase
{
    private const KEYS = __DIR__ . '/../../../Resources/keys';

    protected function setUp(): void
    {
        ContainerSingleton::setContainer(new MockContainer());
    }

    #[Test]
    public function an_xml_signature_made_with_the_sp_key_verifies(): void
    {
        $received = ReceivedAuthnRequestPost::parse(['SAMLRequest' => base64_encode($this->signedRequest())]);

        $this->assertTrue($received->verify($this->publicKey()));
        $this->assertSame('https://sp.example.com/metadata', $received->getAuthnRequest()->getServiceProvider());
    }

    #[Test]
    public function a_request_altered_after_signing_does_not_verify(): void
    {
        $tampered = str_replace('https://sp.example.com/acs', 'https://evil.example.com/acs', $this->signedRequest());
        $received = ReceivedAuthnRequestPost::parse(['SAMLRequest' => base64_encode($tampered)]);

        $this->expectException(Exception::class);
        $received->verify($this->publicKey());
    }

    #[Test]
    public function extensions_are_reloaded_from_the_verified_request(): void
    {
        $received = ReceivedAuthnRequestPost::parse(['SAMLRequest' => base64_encode($this->signedRequest(true))]);
        $extensions = $received->getAuthnRequest()->getExtensions();
        $extensions->getChunks()['Custom']->getValue()->textContent = 'unverified cached value';

        $this->assertTrue($received->verify($this->publicKey()));
        $this->assertSame('signed value', $received->getAuthnRequest()->getExtensions()->getChunks()['Custom']->getValue()->textContent);
    }

    #[Test]
    public function a_post_request_declaring_hmac_is_an_http_bad_request(): void
    {
        $xml = str_replace(C::SIG_RSA_SHA256, C::SIG_HMAC_SHA256, $this->signedRequest());
        $this->expectException(SignatureValidationFailedException::class);
        $this->receiveSignedPost($xml);
    }

    public static function verificationPaths(): iterable
    {
        yield 'direct verification' => [false];
        yield 'POST binding' => [true];
    }

    #[Test]
    #[DataProvider('verificationPaths')]
    public function xpath_transforms_are_rejected_before_signature_verification(bool $throughBinding): void
    {
        $document = DOMDocumentFactory::fromString($this->signedRequest());
        $transform = $document->createElementNS(C::NS_XDSIG, 'ds:Transform');
        $transform->setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
        $xpath = $document->createElementNS(C::NS_XDSIG, 'ds:XPath');
        $xpath->textContent = 'true()';
        $transform->appendChild($xpath);
        $document->getElementsByTagNameNS(C::NS_XDSIG, 'Transforms')->item(0)->appendChild($transform);
        $xml = $document->saveXml($document->documentElement);

        $this->expectException(SignatureValidationFailedException::class);
        $this->expectExceptionMessage('forbidden XML signature Transform');
        if ($throughBinding) {
            $this->receiveSignedPost($xml);
        } else {
            $received = ReceivedAuthnRequestPost::parse(['SAMLRequest' => base64_encode($xml)]);
            $received->verify($this->publicKey());
        }
    }

    #[Test]
    public function a_post_request_signed_with_the_second_rollover_certificate_is_accepted(): void
    {
        $request = $this->receiveSignedPost($this->signedRequest(), [
            __DIR__ . '/../Metadata/keys/entity.crt',
            self::KEYS . '/development_publickey.cer',
        ]);
        $this->assertSame('https://sp.example.com/metadata', $request->getServiceProvider());
    }

    #[Test]
    public function a_post_request_without_a_matching_rollover_certificate_is_rejected(): void
    {
        $this->expectException(SignatureValidationFailedException::class);
        $this->receiveSignedPost($this->signedRequest(), [__DIR__ . '/../Metadata/keys/entity.crt']);
    }

    /**
     * @param list<string> $certificateFiles
     */
    private function receiveSignedPost(string $xml, array $certificateFiles = []): ReceivedAuthnRequest
    {
        $certificates = $certificateFiles ?: [self::KEYS . '/development_publickey.cer'];
        $provider = new ServiceProvider([
            'entityId' => 'https://sp.example.com/metadata',
            'keys' => array_map(static fn (string $file): array => [
                'X509Certificate' => CertificateKeys::certificateDataFromFile($file),
            ], $certificates),
        ]);
        $repository = $this->createMock(ServiceProviderRepository::class);
        $repository->method('hasServiceProvider')->willReturn(true);
        $repository->method('getServiceProvider')->willReturn($provider);
        $logger = new NullLogger();
        $binding = new PostBinding(
            new ResponseProcessor(new KeyLoader(), new PrivateKeyLoader(), $logger),
            new SignatureVerifier(new KeyLoader(), $logger),
            $repository
        );
        $request = Request::create('https://idp.example.com/sso', 'POST', ['SAMLRequest' => base64_encode($xml)]);

        return $binding->receiveSignedAuthnRequestFrom($request);
    }

    private function signedRequest(bool $withExtensions = false): string
    {
        $request = new SAML2AuthnRequest(
            id: IDValue::fromString('_' . bin2hex(random_bytes(16))),
            issueInstant: SAMLDateTimeValue::fromString('2026-11-03T12:00:00Z'),
            assertionConsumerServiceURL: SAMLAnyURIValue::fromString('https://sp.example.com/acs'),
            issuer: new Issuer(SAMLStringValue::fromString('https://sp.example.com/metadata')),
            destination: SAMLAnyURIValue::fromString('https://idp.example.com/sso'),
            extensions: $withExtensions ? new SAML2Extensions([
                new Chunk(DOMDocumentFactory::fromString('<ext:Custom xmlns:ext="urn:example:extension">signed value</ext:Custom>')->documentElement),
            ]) : null,
        );
        $request->sign((new SignatureAlgorithmFactory())->getAlgorithm(
            C::SIG_RSA_SHA256,
            PrivateKey::fromFile(self::KEYS . '/development_privatekey.pem')
        ));

        $xml = $request->toXML();

        return $xml->ownerDocument->saveXml($xml);
    }

    private function publicKey(): PublicKey
    {
        return X509Certificate::fromFile(self::KEYS . '/development_publickey.cer')->getPublicKey();
    }
}
