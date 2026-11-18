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

use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\Type\SAMLStringValue;
use SimpleSAML\SAML2\XML\saml\Issuer;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SAML2AuthnRequest;
use SimpleSAML\XMLSchema\Type\BooleanValue;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Http\Exception\InvalidRequestException;
use Surfnet\SamlBundle\Signing\Signers;
use Symfony\Component\HttpFoundation\Request;

/**
 * @SuppressWarnings("PHPMD.CouplingBetweenObjects")
 */
class AuthnRequestFactory
{
    public static function createUnsignedFromHttpRequest(Request $httpRequest): AuthnRequest
    {
        return AuthnRequest::createUnsigned(
            self::createAuthnRequestFromHttpRequest($httpRequest),
            $httpRequest->get(AuthnRequest::PARAMETER_REQUEST),
            $httpRequest->get(AuthnRequest::PARAMETER_RELAY_STATE)
        );
    }

    /**
     * @deprecated use ReceivedAuthnRequest::from()
     */
    public static function createSignedFromHttpRequest(Request $httpRequest): AuthnRequest
    {
        return AuthnRequest::createSigned(
            self::createAuthnRequestFromHttpRequest($httpRequest),
            $httpRequest->get(AuthnRequest::PARAMETER_REQUEST),
            $httpRequest->get(AuthnRequest::PARAMETER_RELAY_STATE),
            $httpRequest->get(AuthnRequest::PARAMETER_SIGNATURE),
            $httpRequest->get(AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM)
        );
    }

    /**
     * @deprecated use createSignedFromHttpRequest or createUnsignedFromHttpRequest
     */
    public static function createFromHttpRequest(Request $httpRequest): AuthnRequest
    {
        return static::createSignedFromHttpRequest($httpRequest);
    }

    /**
     * @throws \Exception
     */
    private static function createAuthnRequestFromHttpRequest(
        Request $httpRequest
    ): SAML2AuthnRequest {
        // the GET parameter is already urldecoded by Symfony, so we should not do it again.
        $samlRequest = base64_decode((string) $httpRequest->get(AuthnRequest::PARAMETER_REQUEST), true);
        if ($samlRequest === false) {
            throw new InvalidRequestException('Failed decoding the request, did not receive a valid base64 string');
        }

        // Catch any errors gzinflate triggers
        $errorNo = $errorMessage = null;
        set_error_handler(function ($number, $message) use (&$errorNo, &$errorMessage): bool {
            $errorNo = $number;
            $errorMessage = $message;
            return true;
        });
        $samlRequest = gzinflate($samlRequest);
        restore_error_handler();

        if ($samlRequest === false) {
            throw new InvalidRequestException(sprintf(
                'Failed inflating the request; error "%d": "%s"',
                $errorNo,
                $errorMessage
            ));
        }

        return AuthnRequestParser::parseFromHttpRedirectBinding($samlRequest);
    }

    public static function createNewRequest(
        ServiceProvider $serviceProvider,
        IdentityProvider $identityProvider,
        bool $forceAuthn = false,
        string $relayState = ''
    ): AuthnRequest {
        $signer = Signers::forHostedEntity($serviceProvider);

        $request = new SAML2AuthnRequest(
            id: AuthnRequestRebuilder::newId(),
            issueInstant: AuthnRequestRebuilder::now(),
            forceAuthn: $forceAuthn ? BooleanValue::fromBoolean(true) : null,
            assertionConsumerServiceURL: SAMLAnyURIValue::fromString((string) $serviceProvider->getAssertionConsumerUrl()),
            protocolBinding: SAMLAnyURIValue::fromString(Constants::BINDING_HTTP_POST),
            issuer: new Issuer(SAMLStringValue::fromString((string) $serviceProvider->getEntityId())),
            destination: SAMLAnyURIValue::fromString((string) $identityProvider->getSsoUrl()),
        );

        return AuthnRequest::createNew($request, $signer, $relayState);
    }
}
