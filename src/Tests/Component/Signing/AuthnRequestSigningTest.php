<?php declare(strict_types=1);

/**
 * Copyright 2016 SURFnet B.V.
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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\X509;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SAML2AuthnRequest;
use SimpleSAML\XML\DOMDocumentFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use Surfnet\SamlBundle\Http\ReceivedAuthnRequestQueryString;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Surfnet\SamlBundle\Signing\SignatureAlgorithms;
use Surfnet\SamlBundle\Signing\SignatureVerifier;

class AuthnRequestSigningTest extends TestCase
{
    private string $authRequestNoSubject = <<<AUTHNREQUEST_NO_SUBJECT
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    AssertionConsumerServiceIndex="1"
    Destination="https://tiqr.stepup.org/idp/profile/saml2/Redirect/SSO"
    ID="_2b0226190ca1c22de6f66e85f5c95158"
    IssueInstant="2014-09-22T13:42:00Z"
    Version="2.0">
  <saml:Issuer>https://gateway.stepup.org/saml20/sp/metadata</saml:Issuer>
</samlp:AuthnRequest>
AUTHNREQUEST_NO_SUBJECT;

    private ?string $publicKey = null;

    #[Test]
    #[Group('Signing')]
    #[Group('Deprecated')]
    public function deprecated_authn_request_signatures_are_verified_if_the_sender_uses_rfc1738_encoding(): void
    {
        $authnRequestWithDefaultEncoding = $this->createSignedAuthnRequest(
            $this->encodeDataToSignWithPhpsHttpBuildQuery(...)
        );

        $certificate = X509::createFromCertificateData($this->getPublicKey());

        $signatureVerifier    = new SignatureVerifier(new KeyLoader, new NullLogger);
        $signatureWithDefaultEncodingIsVerified = $signatureVerifier->isSignedWith(
            $authnRequestWithDefaultEncoding,
            $certificate
        );

        $this->assertTrue(
            $signatureWithDefaultEncodingIsVerified,
            'The signature of a (deprecated) AuthnRequest signed using data-to-sign encoded'
            . ' according to RFC1738 should be verifiable, but it isn\'t'
        );
    }

    #[Test]
    #[Group('Signing')]
    #[Group('Deprecated')]
    public function deprecated_authn_request_signatures_are_verified_if_the_sender_uses_something_other_than_rfc1738_encoding(): void
    {
        $authnRequestWithCustomEncoding  = $this->createSignedAuthnRequest(
            $this->encodeDataToSignWithCustomHttpQueryEncoding(...)
        );

        $certificate       = X509::createFromCertificateData($this->getPublicKey());
        $signatureVerifier = new SignatureVerifier(new KeyLoader, new NullLogger);

        $signatureWithCustomEncodingIsVerified  = $signatureVerifier->isSignedWith(
            $authnRequestWithCustomEncoding,
            $certificate
        );

        $this->assertFalse(
            $signatureWithCustomEncodingIsVerified,
            'The signature of a (deprecated) AuthnRequest signed using data-to-sign encoded'.
            ' using a custom encoding should not be verifiable, but it is'
        );
    }

    #[Test]
    #[Group('Signing')]
    #[Group('Deprecated')]
    public function deprecated_authn_request_signatures_are_not_verified_if_the_data_to_sign_does_not_correspond_with_the_signature_sent(): void
    {
        $authnRequestWithModifiedDataToSign = $this->createSignedAuthnRequest(
            $this->encodeDataToSignWithPhpsHttpBuildQuery(...),
            'this-is-a-custom-signature'
        );

        $certificate = X509::createFromCertificateData($this->getPublicKey());

        $signatureVerifier   = new SignatureVerifier(new KeyLoader, new NullLogger);
        $signatureIsVerified = $signatureVerifier->isSignedWith($authnRequestWithModifiedDataToSign, $certificate);

        $this->assertFalse(
            $signatureIsVerified,
            'The signature of an AuthnRequest signed using data-to-sign'
            . ' that does not correspond with how it is represented'
            . ' in the http query should not be verifiable but it is'
        );
    }

    #[Test]
    #[Group('Signing')]
    #[Group('Deprecated')]
    public function deprecated_authn_request_signatures_are_not_verified_if_the_parameter_order_of_the_sent_query_is_not_correct(): void
    {
        $authnRequestWithModifiedDataToSign = $this->createSignedAuthnRequest(
            $this->encodeDataToSignUsingIncorrectParameterOrder(...)
        );

        $certificate = X509::createFromCertificateData($this->getPublicKey());

        $signatureVerifier   = new SignatureVerifier(new KeyLoader, new NullLogger);
        $signatureIsVerified = $signatureVerifier->isSignedWith($authnRequestWithModifiedDataToSign, $certificate);

        $this->assertFalse(
            $signatureIsVerified,
            'The signature of an AuthnRequest signed using data-to-sign'
            . ' that corresponds with how it is represented,'
            . ' but with the data-to-sign in the wrong order, should not be verifiable but it is'
        );
    }

    #[Test]
    #[Group('Signing')]
    public function a_received_authn_requests_signature_is_verified_regardless_of_its_encoding(): void
    {
        $signatureVerifier = new SignatureVerifier(new KeyLoader, new NullLogger);
        $certificate       = X509::createFromCertificateData($this->getPublicKey());
        $keyData           = file_get_contents(__DIR__.'/../../../Resources/keys/development_privatekey.pem');
        $privateKey        = self::createSigner($keyData);

        $queryParameters = [
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST => $this->createEncodedSamlRequest(),
            ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM => $privateKey->getAlgorithmId()
        ];

        $dataToSignWithDefaultEncoding = $this->encodeDataToSignWithPhpsHttpBuildQuery($queryParameters);
        $queryParametersWithDefaultEncoding = $queryParameters;
        $queryParametersWithDefaultEncoding[ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE] = base64_encode(
            (string) $privateKey->sign($dataToSignWithDefaultEncoding)
        );
        $rawQueryWithDefaultEncoding = $this->encodeDataToSignWithPhpsHttpBuildQuery($queryParametersWithDefaultEncoding);
        $queryStringWithDefaultEncoding = ReceivedAuthnRequestQueryString::parse($rawQueryWithDefaultEncoding);

        $dataToSignWithCustomEncoding = $this->encodeDataToSignWithCustomHttpQueryEncoding($queryParameters);
        $queryParametersWithCustomEncoding = $queryParameters;
        $queryParametersWithCustomEncoding[ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE] = base64_encode(
            (string) $privateKey->sign($dataToSignWithCustomEncoding)
        );
        $rawQueryWithCustomEncoding = $this->encodeDataToSignWithCustomHttpQueryEncoding(
            $queryParametersWithCustomEncoding
        );
        $queryStringWithCustomEncoding = ReceivedAuthnRequestQueryString::parse($rawQueryWithCustomEncoding);

        $isQueryWithDefaultEncodingSigned = $signatureVerifier->isRequestSignedWith(
            $queryStringWithDefaultEncoding,
            $certificate
        );
        $isQueryWithCustomEncodingSigned  = $signatureVerifier->isRequestSignedWith(
            $queryStringWithCustomEncoding,
            $certificate
        );

        $this->assertTrue(
            $isQueryWithDefaultEncodingSigned,
            'The signature of an AuthnRequest signed using data-to-sign encoded'
            . ' according to RFC1738 should be verifiable, but it isn\'t'
        );
        $this->assertTrue(
            $isQueryWithCustomEncodingSigned,
            'The signature of an AuthnRequest signed using data-to-sign encoded'.
            ' using a custom encoding should be verifiable, but it isn\'t'
        );
    }

    #[Test]
    #[Group('Signing')]
    public function a_received_authn_requests_signature_is_not_verified_if_the_data_to_sign_does_not_correspond_with_the_signature_sent(): void
    {
        $signatureVerifier = new SignatureVerifier(new KeyLoader, new NullLogger);
        $certificate       = X509::createFromCertificateData($this->getPublicKey());
        $keyData           = file_get_contents(__DIR__.'/../../../Resources/keys/development_privatekey.pem');
        $privateKey        = self::createSigner($keyData);

        $queryParameters = [
            ReceivedAuthnRequestQueryString::PARAMETER_REQUEST => $this->createEncodedSamlRequest(),
            ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE_ALGORITHM => $privateKey->getAlgorithmId(),
            ReceivedAuthnRequestQueryString::PARAMETER_SIGNATURE => base64_encode('fake-key')
        ];

        $rawQueryWithDefaultEncoding = $this->encodeDataToSignWithPhpsHttpBuildQuery($queryParameters);
        $queryStringWithDefaultEncoding = ReceivedAuthnRequestQueryString::parse($rawQueryWithDefaultEncoding);

        $isQuerySigned = $signatureVerifier->isRequestSignedWith($queryStringWithDefaultEncoding, $certificate);

        $this->assertFalse(
            $isQuerySigned,
            'The signature of a received AuthnRequest query string'
            . ' that does not correspond with the data-to-sign'
            . ' in the http query should not be verifiable but it is'
        );
    }

    #[Test]
    public function deprecated_verification_does_not_ignore_the_declared_algorithm(): void
    {
        // Sign a query declaring SHA512 with SHA256: the legacy verifier used to ignore that mismatch.
        $request = $this->createSignedAuthnRequest(
            $this->encodeDataToSignWithPhpsHttpBuildQuery(...),
            declaredAlgorithm: C::SIG_RSA_SHA512
        );
        $verifier = new SignatureVerifier(new KeyLoader(), new NullLogger());

        $this->assertFalse($verifier->isSignedWith($request, X509::createFromCertificateData($this->getPublicKey())));
    }

    public static function falsyRelayStates(): iterable
    {
        yield 'empty' => [''];
        yield 'zero' => ['0'];
    }

    #[Test]
    #[DataProvider('falsyRelayStates')]
    public function deprecated_verification_preserves_present_relay_state_values(string $relayState): void
    {
        $request = $this->createSignedAuthnRequest(
            $this->encodeDataToSignWithPhpsHttpBuildQuery(...),
            relayState: $relayState
        );
        $verifier = new SignatureVerifier(new KeyLoader(), new NullLogger());

        $this->assertTrue($verifier->isSignedWith($request, X509::createFromCertificateData($this->getPublicKey())));
    }

    public static function unsignedRequestFactories(): iterable
    {
        yield 'createNew' => [false];
        yield 'createUnsigned' => [true];
    }

    #[Test]
    #[DataProvider('unsignedRequestFactories')]
    public function unsigned_legacy_requests_fail_verification_without_a_type_error(bool $legacy): void
    {
        $xml = SAML2AuthnRequest::fromXML(DOMDocumentFactory::fromString($this->authRequestNoSubject)->documentElement);
        $request = $legacy ? AuthnRequest::createUnsigned($xml, 'raw-request', '') : AuthnRequest::createNew($xml);
        $verifier = new SignatureVerifier(new KeyLoader(), new NullLogger());

        $this->assertFalse($verifier->isSignedWith($request, X509::createFromCertificateData($this->getPublicKey())));
    }

    #[Test]
    public function pss_verification_accepts_pss_padding_and_rejects_pkcs1_padding(): void
    {
        $privateKey = PrivateKey::fromFile(__DIR__ . '/../../../Resources/keys/development_privatekey.pem');
        $publicKey = X509Certificate::fromFile(__DIR__ . '/../../../Resources/keys/development_publickey.cer')->getPublicKey();
        openssl_sign('padding probe', $pss, $privateKey->getMaterial(), 'sha256', OPENSSL_PKCS1_PSS_PADDING);
        openssl_sign('padding probe', $pkcs1, $privateKey->getMaterial(), 'sha256', OPENSSL_PKCS1_PADDING);
        $verifier = SignatureAlgorithms::forVerification(C::SIG_RSA_PSS_SHA256, $publicKey);

        $this->assertTrue($verifier->verify('padding probe', $pss));
        $this->assertFalse($verifier->verify('padding probe', $pkcs1));
    }

    private function encodeDataToSignWithPhpsHttpBuildQuery(array $params): string
    {
        return http_build_query($params);
    }

    private function encodeDataToSignWithCustomHttpQueryEncoding(array $params): string
    {
        $encodedParams = http_build_query($params);

        // Use custom encoding to be incompatible with PHP's RFC1738 or RFC3986, to make sure verification issues would
        // arise if we were solely relying on http_build_query internally
        return str_replace('%3A', ':', $encodedParams);
    }

    private function encodeDataToSignUsingIncorrectParameterOrder(array $params): string
    {
        return http_build_query(array_reverse($params, true));
    }

    /**
     * @param callable $prepareDataToSign Expects an associative array of data to sign and returns a string to sign
     * @param null|string $customSignature Signature to be used instead of signature to sign data to sign with
     */
    private function createSignedAuthnRequest(
        callable $prepareDataToSign,
        ?string $customSignature = null,
        string $declaredAlgorithm = C::SIG_RSA_SHA256,
        ?string $relayState = null,
    ): AuthnRequest {
        $keyData    = file_get_contents(__DIR__.'/../../../Resources/keys/development_privatekey.pem');
        $privateKey = self::createSigner($keyData);

        $domDocument          = DOMDocumentFactory::fromString($this->authRequestNoSubject);
        $unsignedAuthnRequest = SAML2AuthnRequest::fromXML($domDocument->documentElement);

        $requestAsXml   = $unsignedAuthnRequest->toXML()->ownerDocument->saveXml();
        $encodedRequest = base64_encode(gzdeflate($requestAsXml));
        $queryParams    = [AuthnRequest::PARAMETER_REQUEST => $encodedRequest];

        if ($relayState !== null) {
            $queryParams[AuthnRequest::PARAMETER_RELAY_STATE] = $relayState;
        }
        $queryParams[AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM] = $declaredAlgorithm;

        $toSign = $prepareDataToSign($queryParams);
        $signature = $customSignature === null ? base64_encode((string) $privateKey->sign($toSign)) : base64_encode($customSignature);

        $saml2AuthnRequest = $unsignedAuthnRequest;

        return AuthnRequest::createSigned(
            $saml2AuthnRequest,
            $encodedRequest,
            $relayState,
            $signature,
            $declaredAlgorithm
        );
    }

    private function getPublicKey(): string
    {
        if ($this->publicKey === null) {
            $file = file_get_contents(__DIR__.'/../../../Resources/keys/development_publickey.cer');
            $this->publicKey = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'], '', $file);
        }

        return $this->publicKey;
    }

    private function createEncodedSamlRequest(): string
    {
        $domDocument          = DOMDocumentFactory::fromString($this->authRequestNoSubject);
        $unsignedAuthnRequest = SAML2AuthnRequest::fromXML($domDocument->documentElement);
        $requestAsXml         = $unsignedAuthnRequest->toXML()->ownerDocument->saveXml();

        return base64_encode(gzdeflate($requestAsXml));
    }

    private static function createSigner(string $privateKeyPem): SignatureAlgorithmInterface
    {
        return (new SignatureAlgorithmFactory())->getAlgorithm(
            C::SIG_RSA_SHA256,
            new PrivateKey(PEM::fromString($privateKeyPem))
        );
    }
}
