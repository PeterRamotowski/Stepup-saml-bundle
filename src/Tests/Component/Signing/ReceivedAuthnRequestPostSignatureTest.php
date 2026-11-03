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
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Compat\MockContainer;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\Type\SAMLDateTimeValue;
use SimpleSAML\SAML2\Type\SAMLStringValue;
use SimpleSAML\SAML2\XML\saml\Issuer;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SAML2AuthnRequest;
use SimpleSAML\XMLSchema\Type\IDValue;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\PublicKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestPost;

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

    private function signedRequest(): string
    {
        $request = new SAML2AuthnRequest(
            id: IDValue::fromString('_' . bin2hex(random_bytes(16))),
            issueInstant: SAMLDateTimeValue::fromString('2026-11-03T12:00:00Z'),
            assertionConsumerServiceURL: SAMLAnyURIValue::fromString('https://sp.example.com/acs'),
            issuer: new Issuer(SAMLStringValue::fromString('https://sp.example.com/metadata')),
            destination: SAMLAnyURIValue::fromString('https://idp.example.com/sso'),
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
