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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SimpleSAML\SAML2\Assertion\Exception\InvalidAssertionException;
use SimpleSAML\SAML2\Assertion\Exception\InvalidSubjectConfirmationException;
use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Configuration\PrivateKey as PrivateKeyConfiguration;
use SimpleSAML\SAML2\Exception\ProtocolViolationException;
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
use SimpleSAML\XMLSecurity\Exception\AgentUnavailableException;
use SimpleSAML\XMLSecurity\Exception\AuthenticationException;
use SimpleSAML\XMLSecurity\Exception\AuthorizationException;
use SimpleSAML\XMLSecurity\Exception\UnknownKeyException;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Http\Exception\SignatureValidationFailedException;
use Surfnet\SamlBundle\PrivateKeyAgent\KeyMap;
use Surfnet\SamlBundle\SAML2\BridgeContainer;
use Surfnet\SamlBundle\SAML2\Response\AssertionValues;
use Surfnet\SamlBundle\SAML2\Response\ResponseProcessor;
use Surfnet\SamlBundle\Signing\CertificateKeys;
use Surfnet\SamlBundle\Tests\FakePrivateKeyAgent;
use Symfony\Component\Clock\MockClock;
use Throwable;
use TypeError;

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

    /**
     * @var array<string, array{certificate: string, private_key: string}>
     */
    private static array $agentKeys = [];

    public static function setUpBeforeClass(): void
    {
        $directory = sys_get_temp_dir() . '/surfnet-saml-agent-keys-' . bin2hex(random_bytes(4));
        mkdir($directory, 0700);
        self::$agentKeys = [
            'current' => FakePrivateKeyAgent::generateKeyPair($directory, 'current'),
            'previous' => FakePrivateKeyAgent::generateKeyPair($directory, 'previous'),
        ];
    }

    public static function tearDownAfterClass(): void
    {
        foreach (self::$agentKeys as $files) {
            array_map(unlink(...), array_values($files));
        }
        rmdir(dirname(self::$agentKeys['current']['certificate']));
    }

    protected function tearDown(): void
    {
        FakePrivateKeyAgent::unregister();
    }

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
    public function a_signed_response_altered_after_signing_is_rejected(): void
    {
        $tampered = str_replace('john-doe', 'jane-doe', $this->signedResponse($this->response($this->assertion())));

        $this->expectException(InvalidSignatureException::class);

        $this->process($tampered);
    }

    #[Test]
    public function an_attacker_assertion_carrying_the_signature_of_a_wrapped_signed_assertion_is_rejected(): void
    {
        $signed = $this->signedAssertion($this->assertion());

        $this->expectException(InvalidSignatureException::class);

        $this->process($this->response($this->wrapInAttackerAssertion($signed, keepSignature: true)));
    }

    #[Test]
    public function an_unsigned_attacker_assertion_wrapping_a_signed_assertion_is_rejected(): void
    {
        $signed = $this->signedAssertion($this->assertion());

        $this->expectException(UnsignedResponseException::class);

        $this->process($this->response($this->wrapInAttackerAssertion($signed, keepSignature: false)));
    }

    #[Test]
    public function a_response_for_another_destination_does_not_meet_the_preconditions(): void
    {
        $this->expectException(PreconditionNotMetException::class);

        $this->process($this->response(
            $this->signedAssertion($this->assertion()),
            destination: 'https://other.example.com/acs'
        ));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function conditionWindowsOutsideTheCurrentTime(): iterable
    {
        yield 'not yet valid' => ['2026-11-04T12:30:00Z', '2026-11-04T12:45:00Z'];
        yield 'expired' => ['2026-11-04T11:00:00Z', '2026-11-04T11:30:00Z'];
    }

    #[Test]
    #[DataProvider('conditionWindowsOutsideTheCurrentTime')]
    public function an_assertion_outside_its_conditions_window_is_rejected(string $notBefore, string $notOnOrAfter): void
    {
        $this->expectException(InvalidAssertionException::class);

        $this->process($this->response($this->signedAssertion($this->assertion(
            conditionsNotBefore: $notBefore,
            conditionsNotOnOrAfter: $notOnOrAfter,
        ))));
    }

    #[Test]
    public function an_assertion_with_an_expired_subject_confirmation_is_rejected(): void
    {
        $this->expectException(InvalidSubjectConfirmationException::class);

        $this->process($this->response($this->signedAssertion($this->assertion(
            confirmationNotOnOrAfter: '2026-11-04T11:30:00Z',
        ))));
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

    #[Test]
    public function an_agent_service_provider_decrypts_with_exactly_one_agent_call(): void
    {
        $agent = $this->useAgent();

        $assertion = $this->process($this->response($this->encrypted(
            $this->signedAssertion($this->assertion()),
            self::$agentKeys['current']['certificate']
        )));

        $this->assertSame('john-doe', AssertionValues::nameId($assertion));
        $this->assertSame(['/v1/decrypt/sp-decryption'], $agent->requests);
    }

    #[Test]
    public function during_a_rollover_the_previous_agent_key_still_decrypts(): void
    {
        $agent = $this->useAgent();

        $assertion = $this->process($this->response($this->encrypted(
            $this->signedAssertion($this->assertion()),
            self::$agentKeys['previous']['certificate']
        )));

        $this->assertSame('john-doe', AssertionValues::nameId($assertion));
        $this->assertSame(['/v1/decrypt/sp-decryption', '/v1/decrypt/sp-decryption-previous'], $agent->requests);
    }

    #[Test]
    public function a_certificate_named_by_the_encrypted_key_selects_the_agent_key(): void
    {
        $agent = $this->useAgent();
        $previous = self::$agentKeys['previous']['certificate'];

        $assertion = $this->process($this->response($this->encrypted(
            $this->signedAssertion($this->assertion()),
            $previous,
            namedCertificate: $previous
        )));

        $this->assertSame('john-doe', AssertionValues::nameId($assertion));
        $this->assertSame(['/v1/decrypt/sp-decryption-previous'], $agent->requests);
    }

    #[Test]
    public function a_named_certificate_without_an_agent_decryption_key_is_rejected_without_an_agent_call(): void
    {
        $agent = $this->useAgent();

        try {
            $this->process($this->response($this->encrypted(
                $this->signedAssertion($this->assertion()),
                self::$agentKeys['current']['certificate'],
                namedCertificate: self::KEYS . '/development_publickey.cer'
            )));
            $this->fail('An EncryptedKey for an unknown certificate must be rejected.');
        } catch (InvalidAssertionException $exception) {
            $this->assertStringContainsString('no agent decryption key', $exception->getMessage());
        }

        $this->assertSame([], $agent->requests);
    }

    #[Test]
    public function an_assertion_that_no_agent_key_can_decrypt_is_rejected(): void
    {
        $agent = $this->useAgent();

        try {
            $this->process($this->response($this->encrypted(
                $this->signedAssertion($this->assertion()),
                self::KEYS . '/development_publickey.cer'
            )));
            $this->fail('An assertion for another key must be rejected.');
        } catch (InvalidAssertionException $exception) {
            $this->assertSame('The assertion could not be decrypted with any agent key', $exception->getMessage());
        }

        $this->assertCount(2, $agent->requests);
    }

    /**
     * @return iterable<string, array{int, class-string<Throwable>}>
     */
    public static function agentFailures(): iterable
    {
        yield 'unavailable' => [503, AgentUnavailableException::class];
        yield 'rate limited' => [429, AgentUnavailableException::class];
        yield 'invalid token' => [401, AuthenticationException::class];
        yield 'unauthorised key' => [403, AuthorizationException::class];
        yield 'unknown key' => [404, UnknownKeyException::class];
    }

    /**
     * @param class-string<Throwable> $expected
     */
    #[Test]
    #[DataProvider('agentFailures')]
    public function an_agent_failure_ends_decryption_without_trying_another_key(int $status, string $expected): void
    {
        $agent = $this->useAgent();
        $agent->status = $status;

        try {
            $this->process($this->response($this->encrypted(
                $this->signedAssertion($this->assertion()),
                self::$agentKeys['previous']['certificate']
            )));
            $this->fail('An agent failure must fail the decryption.');
        } catch (Throwable $exception) {
            $this->assertInstanceOf($expected, $exception);
            $this->assertStringNotContainsString(FakePrivateKeyAgent::TOKEN, (string) $exception);
        }

        $this->assertSame(['/v1/decrypt/sp-decryption'], $agent->requests);
    }

    #[Test]
    public function an_agent_service_provider_without_agent_decryption_keys_cannot_decrypt(): void
    {
        $this->useAgent();
        $this->processor = new ResponseProcessor(new KeyLoader(), new PrivateKeyLoader(), new NullLogger());

        $this->expectException(InvalidAssertionException::class);
        $this->expectExceptionMessage('no agent key may decrypt');

        $this->process($this->response($this->encrypted(
            $this->signedAssertion($this->assertion()),
            self::$agentKeys['current']['certificate']
        )));
    }

    #[Test]
    public function hmac_signature_methods_are_rejected_without_a_type_error(): void
    {
        $xml = str_replace(C::SIG_RSA_SHA256, C::SIG_HMAC_SHA256, $this->signedAssertion($this->assertion()));
        $this->expectException(InvalidSignatureException::class);
        $this->process($this->response($xml));
    }

    #[Test]
    public function an_unregistered_agent_key_transport_is_rejected_without_an_agent_call(): void
    {
        $agent = $this->useAgent();
        KeyTransportAlgorithmFactory::unregisterAlgorithmFactory(C::KEY_TRANSPORT_OAEP_MGF1P);
        $encrypted = $this->encrypted($this->signedAssertion($this->assertion()), self::$agentKeys['current']['certificate']);
        try {
            $this->process($this->response($encrypted));
            $this->fail('Unregistered agent key transport must be rejected.');
        } catch (InvalidAssertionException $exception) {
            $this->assertInstanceOf(TypeError::class, $exception->getPrevious());
        }
        $this->assertSame([], $agent->requests);
    }

    #[Test]
    public function legacy_assertion_accessors_trim_text_values(): void
    {
        $xml = str_replace(
            ['>john-doe<', '>' . self::IDP_ENTITY_ID . '<', '<saml:Issuer>', '</saml:Assertion>'],
            [">\n  john-doe  \n<", ">\n  " . self::IDP_ENTITY_ID . "  \n<",
                '<saml:Issuer Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">',
                '<saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>'
                . "\n  student  \n" . '</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>'],
            $this->assertion()
        );
        $assertion = $this->process($this->response($this->signedAssertion($xml)));
        $this->assertSame('john-doe', AssertionValues::nameId($assertion));
        $this->assertSame(self::IDP_ENTITY_ID, AssertionValues::issuer($assertion));
        $this->assertSame(['role' => ['student']], AssertionValues::attributes($assertion));
    }

    public static function signatureLocations(): iterable
    {
        yield 'Response signature' => ['response'];
        yield 'Assertion signature' => ['assertion'];
        yield 'encrypted Assertion signature' => ['encrypted'];
    }

    #[Test]
    #[DataProvider('signatureLocations')]
    public function direct_response_processing_rejects_xpath_transforms(string $location): void
    {
        $xml = $location === 'response'
            ? $this->signedResponse($this->response($this->assertion()))
            : $this->signedAssertion($this->assertion());
        $document = DOMDocumentFactory::fromString($xml);
        $transform = $document->createElementNS(C::NS_XDSIG, 'ds:Transform');
        $transform->setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
        $xpath = $document->createElementNS(C::NS_XDSIG, 'ds:XPath');
        $xpath->textContent = 'true()';
        $transform->appendChild($xpath);
        $document->getElementsByTagNameNS(C::NS_XDSIG, 'Transforms')->item(0)->appendChild($transform);
        $xml = $document->saveXml($document->documentElement);
        if ($location === 'encrypted') {
            $xml = $this->encrypted($xml);
        }

        $this->expectException(SignatureValidationFailedException::class);
        $this->expectExceptionMessage('forbidden XML signature Transform');
        $this->process($location === 'response' ? $xml : $this->response($xml));
    }

    #[Test]
    public function default_entity_format_issuers_with_surrounding_whitespace_are_rejected_during_parsing(): void
    {
        $xml = str_replace(
            '>' . self::IDP_ENTITY_ID . '<',
            ">\n " . self::IDP_ENTITY_ID . " \n<",
            $this->assertion()
        );
        $this->expectException(ProtocolViolationException::class);
        Assertion::fromXML(DOMDocumentFactory::fromString($xml)->documentElement);
    }

    private function useAgent(): FakePrivateKeyAgent
    {
        $keyMap = new KeyMap([
            'sp-decryption' => ['certificate_file' => self::$agentKeys['current']['certificate'], 'operations' => ['decrypt']],
            'sp-decryption-previous' => [
                'certificate_file' => self::$agentKeys['previous']['certificate'],
                'operations' => ['decrypt'],
            ],
        ], []);
        $agent = new FakePrivateKeyAgent([
            'sp-decryption' => self::$agentKeys['current']['private_key'],
            'sp-decryption-previous' => self::$agentKeys['previous']['private_key'],
        ]);
        $agent->register($keyMap);

        $this->processor = new ResponseProcessor(new KeyLoader(), new PrivateKeyLoader(), new NullLogger(), $keyMap);
        $this->serviceProvider = new ServiceProvider([
            'entityId' => self::SP_ENTITY_ID,
            'assertionConsumerUrl' => self::ACS,
            'certificateFile' => self::$agentKeys['current']['certificate'],
            'privateKeys' => [],
            'privateKeyAgent' => true,
        ]);

        return $agent;
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
        string $conditionsNotBefore = '2026-11-04T11:55:00Z',
        string $conditionsNotOnOrAfter = '2026-11-04T12:05:00Z',
        string $confirmationNotOnOrAfter = '2026-11-04T12:05:00Z',
    ): string {
        return sprintf(
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%s" Version="2.0"'
            . ' IssueInstant="2026-11-04T12:00:00Z"><saml:Issuer>%s</saml:Issuer>'
            . '<saml:Subject><saml:NameID>john-doe</saml:NameID>'
            . '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            . '<saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s" InResponseTo="%s"/>'
            . '</saml:SubjectConfirmation></saml:Subject>'
            . '<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">'
            . '<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
            . '<saml:AuthnStatement AuthnInstant="2026-11-04T12:00:00Z" SessionNotOnOrAfter="%s"><saml:AuthnContext>'
            . '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
            . '</saml:AuthnContext></saml:AuthnStatement></saml:Assertion>',
            bin2hex(random_bytes(16)),
            self::IDP_ENTITY_ID,
            $confirmationNotOnOrAfter,
            $recipient,
            $inResponseTo,
            $conditionsNotBefore,
            $conditionsNotOnOrAfter,
            $audience,
            $sessionNotOnOrAfter
        );
    }

    private function response(string $assertions, string $destination = self::ACS): string
    {
        return sprintf(
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            . ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%s" Version="2.0"'
            . ' IssueInstant="2026-11-04T12:00:00Z" Destination="%s" InResponseTo="%s">'
            . '<saml:Issuer>%s</saml:Issuer><samlp:Status>'
            . '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>%s</samlp:Response>',
            bin2hex(random_bytes(16)),
            $destination,
            self::REQUEST_ID,
            self::IDP_ENTITY_ID,
            $assertions
        );
    }

    /**
     * Signature wrapping: an attacker copy of the signed assertion, with another NameID, wraps the original in Advice.
     */
    private function wrapInAttackerAssertion(string $signedAssertionXml, bool $keepSignature): string
    {
        $document = DOMDocumentFactory::fromString(str_replace('john-doe', 'attacker', $signedAssertionXml));
        $attacker = $document->documentElement;
        if (!$keepSignature) {
            $signature = $document->getElementsByTagNameNS(C::NS_XDSIG, 'Signature')->item(0);
            $signature->parentNode->removeChild($signature);
        }

        $advice = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Advice');
        $advice->appendChild($document->importNode(
            DOMDocumentFactory::fromString($signedAssertionXml)->documentElement,
            true
        ));
        $attacker->insertBefore(
            $advice,
            $document->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'AuthnStatement')->item(0)
        );

        return $document->saveXml($attacker);
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

    private function encrypted(
        string $assertionXml,
        string $certificateFile = self::KEYS . '/development_publickey.cer',
        ?string $namedCertificate = null,
    ): string {
        $assertion = Assertion::fromXML(DOMDocumentFactory::fromString($assertionXml)->documentElement);
        $encryptor = (new KeyTransportAlgorithmFactory())->getAlgorithm(
            C::KEY_TRANSPORT_OAEP_MGF1P,
            X509Certificate::fromFile($certificateFile)->getPublicKey()
        );
        $xml = (new EncryptedAssertion($assertion->encrypt($encryptor)))->toXML();
        if ($namedCertificate === null) {
            return $xml->ownerDocument->saveXml($xml);
        }

        // Name the recipient certificate in the EncryptedKey, as some IdPs do.
        $document = DOMDocumentFactory::fromString($xml->ownerDocument->saveXml($xml));
        $cipherData = $document->getElementsByTagNameNS(C::NS_XENC, 'EncryptedKey')->item(0)
            ->getElementsByTagNameNS(C::NS_XENC, 'CipherData')->item(0);
        $keyInfo = $document->createElementNS(C::NS_XDSIG, 'ds:KeyInfo');
        $x509Data = $keyInfo->appendChild($document->createElementNS(C::NS_XDSIG, 'ds:X509Data'));
        $certificateElement = $document->createElementNS(C::NS_XDSIG, 'ds:X509Certificate');
        $certificateElement->textContent = CertificateKeys::certificateDataFromFile($namedCertificate);
        $x509Data->appendChild($certificateElement);
        $cipherData->parentNode->insertBefore($keyInfo, $cipherData);

        return $document->saveXml($document->documentElement);
    }

    private function privateKey(): PrivateKey
    {
        return PrivateKey::fromFile(self::KEYS . '/development_privatekey.pem');
    }
}
