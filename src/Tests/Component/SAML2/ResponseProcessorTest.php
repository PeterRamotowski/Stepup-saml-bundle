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

namespace Surfnet\SamlBundle\Tests\Component\SAML2;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SimpleSAML\SAML2\Assertion\Exception\InvalidAssertionException;
use SimpleSAML\SAML2\Assertion\Exception\InvalidSubjectConfirmationException;
use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Configuration\PrivateKey as PrivateKeyConfiguration;
use SimpleSAML\SAML2\Response\Exception\InvalidResponseException;
use SimpleSAML\SAML2\Response\Exception\InvalidSignatureException;
use SimpleSAML\SAML2\Response\Exception\PreconditionNotMetException;
use SimpleSAML\SAML2\Response\Exception\UnsignedResponseException;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\EncryptedAssertion;
use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\KeyTransportAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\SAML2\BridgeContainer;
use Surfnet\SamlBundle\SAML2\Response\AssertionValues;
use Surfnet\SamlBundle\SAML2\Response\ResponseProcessor;
use Symfony\Component\Clock\MockClock;

class ResponseProcessorTest extends TestCase
{
    private const KEYS = __DIR__ . '/../../../Resources/keys';
    private const ACS = 'https://sp.example.com/acs';
    private const SP_ENTITY_ID = 'https://sp.example.com/metadata';
    private const IDP_ENTITY_ID = 'https://idp.example.com/metadata';
    private const REQUEST_ID = '_request';

    private ResponseProcessor $processor;
    private ServiceProvider $serviceProvider;
    private IdentityProvider $identityProvider;

    protected function setUp(): void
    {
        ContainerSingleton::setContainer(new BridgeContainer(new NullLogger(), new MockClock('2026-11-04T12:00:00Z')));

        $this->processor = new ResponseProcessor(new KeyLoader(), new PrivateKeyLoader(), new NullLogger());
        $this->serviceProvider = new ServiceProvider([
            'entityId' => self::SP_ENTITY_ID,
            'assertionConsumerUrl' => self::ACS,
            'privateKeys' => [
                new PrivateKeyConfiguration(self::KEYS . '/development_privatekey.pem', PrivateKeyConfiguration::NAME_DEFAULT),
            ],
        ]);
        $this->identityProvider = new IdentityProvider([
            'entityId' => self::IDP_ENTITY_ID,
            'certificateFile' => self::KEYS . '/development_publickey.cer',
        ]);
    }

    #[Test]
    public function a_signed_assertion_in_an_unsigned_response_is_accepted(): void
    {
        $assertion = $this->process($this->response($this->signedAssertion($this->assertion())));

        $this->assertSame('john-doe', AssertionValues::nameId($assertion));
    }

    #[Test]
    public function an_unsigned_assertion_in_a_signed_response_is_accepted(): void
    {
        $assertion = $this->process($this->signedResponse($this->response($this->assertion())));

        $this->assertSame(self::IDP_ENTITY_ID, AssertionValues::issuer($assertion));
    }

    #[Test]
    public function an_encrypted_signed_assertion_is_decrypted_with_the_sp_key(): void
    {
        $assertion = $this->process($this->response($this->encrypted($this->signedAssertion($this->assertion()))));

        $this->assertSame('john-doe', AssertionValues::nameId($assertion));
    }

    #[Test]
    public function an_entirely_unsigned_response_is_rejected(): void
    {
        $this->expectException(UnsignedResponseException::class);

        $this->process($this->response($this->assertion()));
    }

    #[Test]
    public function an_assertion_altered_after_signing_is_rejected(): void
    {
        $tampered = str_replace('john-doe', 'jane-doe', $this->signedAssertion($this->assertion()));

        $this->expectException(InvalidSignatureException::class);

        $this->process($this->response($tampered));
    }

    #[Test]
    public function a_signature_with_a_blacklisted_algorithm_is_rejected(): void
    {
        $this->expectException(InvalidSignatureException::class);

        $this->process($this->response($this->signedAssertion($this->assertion(), C::SIG_RSA_SHA1)));
    }

    #[Test]
    public function a_response_that_is_not_a_success_does_not_meet_the_preconditions(): void
    {
        $response = str_replace(
            'urn:oasis:names:tc:SAML:2.0:status:Success',
            'urn:oasis:names:tc:SAML:2.0:status:Responder',
            $this->response($this->signedAssertion($this->assertion()))
        );

        $this->expectException(PreconditionNotMetException::class);

        $this->process($response);
    }

    #[Test]
    public function a_response_with_two_assertions_is_rejected(): void
    {
        $signed = $this->signedAssertion($this->assertion());

        $this->expectException(InvalidResponseException::class);
        $this->expectExceptionMessage('Expected exactly one assertion, found 2');

        $this->process($this->response($signed . $this->signedAssertion($this->assertion())));
    }

    #[Test]
    public function an_encrypted_assertion_with_a_second_encrypted_key_in_its_key_info_is_rejected(): void
    {
        $document = DOMDocumentFactory::fromString($this->encrypted($this->signedAssertion($this->assertion())));
        $encryptedKey = $document->getElementsByTagNameNS(C::NS_XENC, 'EncryptedKey')->item(0);
        $encryptedKey->parentNode->appendChild($encryptedKey->cloneNode(true));

        $this->expectException(InvalidAssertionException::class);
        $this->expectExceptionMessage('Expected exactly one EncryptedKey in the EncryptedAssertion, found 2');

        $this->process($this->response($document->saveXml($document->documentElement)));
    }

    #[Test]
    public function an_encrypted_assertion_with_a_second_encrypted_key_next_to_its_data_is_rejected(): void
    {
        $document = DOMDocumentFactory::fromString($this->encrypted($this->signedAssertion($this->assertion())));
        $encryptedKey = $document->getElementsByTagNameNS(C::NS_XENC, 'EncryptedKey')->item(0);
        $document->documentElement->appendChild($encryptedKey->cloneNode(true));

        $this->expectException(InvalidAssertionException::class);
        $this->expectExceptionMessage('Expected exactly one EncryptedKey in the EncryptedAssertion, found 2');

        $this->process($this->response($document->saveXml($document->documentElement)));
    }

    #[Test]
    public function an_encrypted_assertion_without_an_encrypted_key_is_rejected(): void
    {
        $document = DOMDocumentFactory::fromString($this->encrypted($this->signedAssertion($this->assertion())));
        $keyInfo = $document->getElementsByTagNameNS(C::NS_XDSIG, 'KeyInfo')->item(0);
        $keyInfo->parentNode->removeChild($keyInfo);

        $this->expectException(InvalidAssertionException::class);
        $this->expectExceptionMessage('Expected exactly one EncryptedKey in the EncryptedAssertion, found 0');

        $this->process($this->response($document->saveXml($document->documentElement)));
    }

    #[Test]
    public function an_assertion_with_an_expired_session_is_rejected(): void
    {
        $this->expectException(InvalidAssertionException::class);

        $this->process($this->response($this->signedAssertion($this->assertion(sessionNotOnOrAfter: '2026-11-04T11:00:00Z'))));
    }

    #[Test]
    public function an_assertion_for_another_audience_is_rejected(): void
    {
        $this->expectException(InvalidAssertionException::class);

        $this->process($this->response($this->signedAssertion($this->assertion(audience: 'https://other.example.com/metadata'))));
    }

    #[Test]
    public function an_assertion_for_another_recipient_is_rejected(): void
    {
        $this->expectException(InvalidSubjectConfirmationException::class);

        $this->process($this->response($this->signedAssertion($this->assertion(recipient: 'https://other.example.com/acs'))));
    }

    #[Test]
    public function an_assertion_in_response_to_another_request_is_rejected(): void
    {
        $this->expectException(InvalidSubjectConfirmationException::class);

        $this->process($this->response($this->signedAssertion($this->assertion(inResponseTo: '_other'))));
    }

    private function process(string $responseXml): Assertion
    {
        return $this->processor->process(
            $this->serviceProvider,
            $this->identityProvider,
            self::ACS,
            Response::fromXML(DOMDocumentFactory::fromString($responseXml)->documentElement)
        );
    }

    private function assertion(
        string $sessionNotOnOrAfter = '2026-11-04T20:00:00Z',
        string $audience = self::SP_ENTITY_ID,
        string $recipient = self::ACS,
        string $inResponseTo = self::REQUEST_ID,
    ): string {
        return sprintf(
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%s" Version="2.0"'
            . ' IssueInstant="2026-11-04T12:00:00Z"><saml:Issuer>%s</saml:Issuer>'
            . '<saml:Subject><saml:NameID>john-doe</saml:NameID>'
            . '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            . '<saml:SubjectConfirmationData NotOnOrAfter="2026-11-04T12:05:00Z" Recipient="%s" InResponseTo="%s"/>'
            . '</saml:SubjectConfirmation></saml:Subject>'
            . '<saml:Conditions NotBefore="2026-11-04T11:55:00Z" NotOnOrAfter="2026-11-04T12:05:00Z">'
            . '<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
            . '<saml:AuthnStatement AuthnInstant="2026-11-04T12:00:00Z" SessionNotOnOrAfter="%s"><saml:AuthnContext>'
            . '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
            . '</saml:AuthnContext></saml:AuthnStatement></saml:Assertion>',
            bin2hex(random_bytes(16)),
            self::IDP_ENTITY_ID,
            $recipient,
            $inResponseTo,
            $audience,
            $sessionNotOnOrAfter
        );
    }

    private function response(string $assertions): string
    {
        return sprintf(
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%s" Version="2.0"'
            . ' IssueInstant="2026-11-04T12:00:00Z" Destination="%s" InResponseTo="%s">'
            . '<saml:Issuer>%s</saml:Issuer><samlp:Status>'
            . '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>%s</samlp:Response>',
            bin2hex(random_bytes(16)),
            self::ACS,
            self::REQUEST_ID,
            self::IDP_ENTITY_ID,
            $assertions
        );
    }

    private function signedAssertion(string $assertionXml, string $algorithm = C::SIG_RSA_SHA256): string
    {
        $assertion = Assertion::fromXML(DOMDocumentFactory::fromString($assertionXml)->documentElement);
        $assertion->sign((new SignatureAlgorithmFactory([]))->getAlgorithm($algorithm, $this->privateKey()));
        $xml = $assertion->toXML();

        return $xml->ownerDocument->saveXml($xml);
    }

    private function signedResponse(string $responseXml): string
    {
        $response = Response::fromXML(DOMDocumentFactory::fromString($responseXml)->documentElement);
        $response->sign((new SignatureAlgorithmFactory())->getAlgorithm(C::SIG_RSA_SHA256, $this->privateKey()));
        $xml = $response->toXML();

        return $xml->ownerDocument->saveXml($xml);
    }

    private function encrypted(string $assertionXml): string
    {
        $assertion = Assertion::fromXML(DOMDocumentFactory::fromString($assertionXml)->documentElement);
        $encryptor = (new KeyTransportAlgorithmFactory())->getAlgorithm(
            C::KEY_TRANSPORT_OAEP_MGF1P,
            X509Certificate::fromFile(self::KEYS . '/development_publickey.cer')->getPublicKey()
        );
        $xml = (new EncryptedAssertion($assertion->encrypt($encryptor)))->toXML();

        return $xml->ownerDocument->saveXml($xml);
    }

    private function privateKey(): PrivateKey
    {
        return PrivateKey::fromFile(self::KEYS . '/development_privatekey.pem');
    }
}
