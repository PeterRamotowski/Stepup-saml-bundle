<?php declare(strict_types=1);

/**
 * Copyright 2014 SURFnet bv
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

namespace Surfnet\SamlBundle\SAML2;

use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SAML2AuthnRequest;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\Http\Exception\InvalidRequestException;
use Surfnet\SamlBundle\SAML2\Extensions\ExtensionsMapperTrait;

class AuthnRequest
{
    use AuthnRequestAccessorsTrait;
    use ExtensionsMapperTrait;

    final public const PARAMETER_RELAY_STATE = 'RelayState';
    final public const PARAMETER_REQUEST = 'SAMLRequest';
    final public const PARAMETER_SIGNATURE = 'Signature';
    final public const PARAMETER_SIGNATURE_ALGORITHM = 'SigAlg';

    private ?string $rawRequest = null;

    private ?string $signature = null;

    private ?string $signatureAlgorithm = null;

    private ?string $relayState = null;

    private ?SignatureAlgorithmInterface $signer = null;

    private function __construct(private SAML2AuthnRequest $request)
    {
        $this->loadExtensionsFromSaml2AuthNRequest();
    }

    /**
     * @deprecated use ReceivedAuthnRequest::from()
     */
    public static function createUnsigned(
        SAML2AuthnRequest $request,
        string $rawRequest,
        string $relayState
    ): self {
        $authnRequest = new self($request);
        $authnRequest->rawRequest = $rawRequest;
        if ($relayState !== '' && $relayState !== '0') {
            $authnRequest->relayState = $relayState;
        }

        return $authnRequest;
    }

    /**
     * @deprecated use ReceivedAuthnRequest::from()
     */
    public static function createSigned(
        SAML2AuthnRequest $request,
        string $rawRequest,
        ?string $relayState,
        string $signature,
        string $signatureAlgorithm
    ): self {
        $authnRequest = new self($request);
        $authnRequest->rawRequest = $rawRequest;
        if ($relayState !== null) {
            $authnRequest->relayState = $relayState;
        }
        $decodedSignature = base64_decode($signature, true);
        if ($decodedSignature === false || $decodedSignature === '') {
            throw new InvalidRequestException('The AuthnRequest signature must be a non-empty base64 string');
        }
        $authnRequest->signature = $decodedSignature;
        $authnRequest->signatureAlgorithm = $signatureAlgorithm;

        return $authnRequest;
    }

    /**
     * @deprecated use ReceivedAuthnRequest::from()
     */
    public static function create(
        SAML2AuthnRequest $request,
        string $rawRequest,
        ?string $relayState,
        string $signature,
        string $signatureAlgorithm
    ): self {
        return static::createSigned(
            $request,
            $rawRequest,
            $relayState,
            $signature,
            $signatureAlgorithm
        );
    }

    public static function createNew(
        SAML2AuthnRequest $req,
        ?SignatureAlgorithmInterface $signer = null,
        ?string $relayState = null
    ): self {
        $authnRequest = new self($req);
        $authnRequest->signer = $signer;
        if ($relayState !== null && $relayState !== '') {
            $authnRequest->relayState = $relayState;
        }

        return $authnRequest;
    }

    public function getNameId(): ?string
    {
        $nameId = $this->getRequestNameId()?->getContent()->getValue();

        if ($nameId === null || $nameId === '' || $nameId === '0') {
            return null;
        }

        return $nameId;
    }

    public function isSigned(): bool
    {
        return $this->signature !== null && $this->signature !== '';
    }

    public function getAssertionConsumerServiceURL(): ?string
    {
        return $this->request->getAssertionConsumerServiceURL()?->getValue();
    }

    public function getDestination(): string
    {
        return $this->request->getDestination()?->getValue()
            ?? throw new RuntimeException('The AuthnRequest has no Destination');
    }

    public function getServiceProvider(): string
    {
        return $this->request->getIssuer()?->getContent()->getValue()
            ?? throw new RuntimeException('The AuthnRequest has no Issuer');
    }

    /**
     * @return null|string
     */
    public function getSignature(): ?string
    {
        return $this->signature;
    }

    public function getSignatureAlgorithm(): string
    {
        return $this->signatureAlgorithm;
    }

    /**
     * The signed HTTP-Redirect query; requires the signer passed to createNew().
     */
    public function buildRequestQuery(): string
    {
        return $this->signRequestQuery($this->buildQueryParameters());
    }

    /**
     * The HTTP-Redirect query of a request created without a signer: SAMLRequest and optional RelayState only.
     *
     * A request created with a signer is never encoded unsigned, so a signing failure cannot fall back to this path.
     */
    public function buildUnsignedRequestQuery(): string
    {
        if ($this->signer instanceof SignatureAlgorithmInterface) {
            throw new RuntimeException('Cannot build an unsigned request query: the request was created with a signer');
        }

        return http_build_query($this->buildQueryParameters());
    }

    /**
     * @return array<string, string>
     */
    private function buildQueryParameters(): array
    {
        $queryParams = [self::PARAMETER_REQUEST => base64_encode(gzdeflate($this->getUnsignedXML()))];

        if ($this->relayState !== null) {
            $queryParams[self::PARAMETER_RELAY_STATE] = $this->relayState;
        }

        return $queryParams;
    }

    public function getSignedRequestQuery(): string
    {
        $queryParams = [self::PARAMETER_REQUEST => $this->rawRequest];

        if ($this->relayState !== null) {
            $queryParams[self::PARAMETER_RELAY_STATE] = $this->relayState;
        }

        $queryParams[self::PARAMETER_SIGNATURE_ALGORITHM] = $this->signatureAlgorithm;

        return http_build_query($queryParams);
    }

    private function signRequestQuery(array $queryParams): string
    {
        $signer = $this->signer;
        if (!$signer instanceof SignatureAlgorithmInterface) {
            throw new RuntimeException('Cannot build a signed request query: no signer was provided');
        }
        $queryParams[self::PARAMETER_SIGNATURE_ALGORITHM] = $signer->getAlgorithmId();

        // The HTTP-Redirect signature covers these exact encoded query bytes, not the XML message.
        $toSign = http_build_query($queryParams);
        $signature = $signer->sign($toSign);

        return $toSign . '&Signature=' . urlencode(base64_encode((string) $signature));
    }
}
