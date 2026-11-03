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

namespace Surfnet\SamlBundle\SAML2;

use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SAML2AuthnRequest;
use SimpleSAML\XMLSecurity\Key\PublicKey;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\SAML2\Extensions\ExtensionsMapperTrait;
use Surfnet\SamlBundle\Signing\SignatureAlgorithms;

final class ReceivedAuthnRequest
{
    use AuthnRequestAccessorsTrait;
    use ExtensionsMapperTrait;

    private function __construct(private SAML2AuthnRequest $request)
    {
        $this->loadExtensionsFromSaml2AuthNRequest();
    }

    public static function from(string $decodedSamlRequest): ReceivedAuthnRequest
    {
        return new self(AuthnRequestParser::parse($decodedSamlRequest));
    }

    /**
     * Use for HTTP-Redirect requests only; see AuthnRequestParser::parseFromHttpRedirectBinding().
     */
    public static function fromHttpRedirectBinding(string $decodedSamlRequest): ReceivedAuthnRequest
    {
        return new self(AuthnRequestParser::parseFromHttpRedirectBinding($decodedSamlRequest));
    }

    public function getNameId(): ?string
    {
        return $this->getRequestNameId()?->getContent()->getValue();
    }

    public function getDestination(): ?string
    {
        return $this->request->getDestination()?->getValue();
    }

    public function getServiceProvider(): ?string
    {
        return $this->request->getIssuer()?->getContent()->getValue();
    }

    public function getAssertionConsumerServiceURL(): string
    {
        return $this->request->getAssertionConsumerServiceURL()?->getValue()
            ?? throw new RuntimeException('The AuthnRequest has no AssertionConsumerServiceURL');
    }

    public function getScopingRequesterIds(): array
    {
        return array_map(
            static fn ($requesterId): string => $requesterId->getContent()->getValue(),
            $this->request->getScoping()?->getRequesterId() ?? []
        );
    }

    /**
     * @throws \Exception when the signature is invalid
     */
    public function verify(PublicKey $publicKey): bool
    {
        $signature = $this->request->getSignature();
        if ($signature === null) {
            return false;
        }

        $verifier = SignatureAlgorithms::factory()->getAlgorithm(
            $signature->getSignedInfo()->getSignatureMethod()->getAlgorithm()->getValue(),
            $publicKey
        );

        // Continue with the request as covered by the signature, not the document it was found in.
        $verified = $this->request->verify($verifier);
        if (!$verified instanceof SAML2AuthnRequest) {
            throw new RuntimeException('The verified message is not an AuthnRequest');
        }
        $this->request = $verified;

        return true;
    }
}
