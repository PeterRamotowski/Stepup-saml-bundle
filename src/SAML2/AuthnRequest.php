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

use RobRichards\XMLSecLibs\XMLSecurityKey;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SAML2AuthnRequest;
use Surfnet\SamlBundle\Exception\RuntimeException;
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

    private ?XMLSecurityKey $signingKey = null;

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
        if ($relayState) {
            $authnRequest->relayState = $relayState;
        }
        $authnRequest->signature = base64_decode($signature, true);
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
        ?XMLSecurityKey $signingKey = null,
        ?string $relayState = null
    ): self {
        $authnRequest = new self($req);
        $authnRequest->signingKey = $signingKey;
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

    public function buildRequestQuery(): string
    {
        $requestAsXml = $this->getUnsignedXML();
        $encodedRequest = base64_encode(gzdeflate($requestAsXml));
        $queryParams = [self::PARAMETER_REQUEST => $encodedRequest];

        if ($this->relayState !== null) {
            $queryParams[self::PARAMETER_RELAY_STATE] = $this->relayState;
        }

        return $this->signRequestQuery($queryParams);
    }

    public function getSignedRequestQuery(): string
    {
        $queryParams = [self::PARAMETER_REQUEST => $this->rawRequest];

        if ($this->relayState) {
            $queryParams[self::PARAMETER_RELAY_STATE] = $this->relayState;
        }

        $queryParams[self::PARAMETER_SIGNATURE_ALGORITHM] = $this->signatureAlgorithm;

        return http_build_query($queryParams);
    }

    private function signRequestQuery(array $queryParams): string
    {
        $securityKey = $this->signingKey;
        if (!$securityKey instanceof XMLSecurityKey) {
            throw new RuntimeException('Cannot build a signed request query: no signing key was provided');
        }
        $queryParams[self::PARAMETER_SIGNATURE_ALGORITHM] = $securityKey->type;

        $toSign = http_build_query($queryParams);
        $signature = $securityKey->signData($toSign);

        return $toSign . '&Signature=' . urlencode(base64_encode((string) $signature));
    }
}
