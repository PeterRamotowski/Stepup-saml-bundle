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

namespace Surfnet\SamlBundle\SAML2;

use Dom\Element;
use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SAML2AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\MessageFactory;
use SimpleSAML\XML\DOMDocumentFactory;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;
use Surfnet\SamlBundle\Exception\RuntimeException;
use function sprintf;

/**
 * @internal
 */
final class AuthnRequestParser
{
    public static function parse(string $decodedSamlRequest): SAML2AuthnRequest
    {
        return self::fromElement(self::loadDocumentElement($decodedSamlRequest));
    }

    /**
     * For HTTP-Redirect requests, whose signature covers the query string rather than the XML: removes
     * AllowCreate="true" from a transient NameIDPolicy, which saml2 v7 rejects (SAML 2.0 errata E14) but
     * many service providers still send. Requests with an XML signature must not be altered, so they stay strict.
     */
    public static function parseFromHttpRedirectBinding(string $decodedSamlRequest): SAML2AuthnRequest
    {
        $element = self::loadDocumentElement($decodedSamlRequest);

        foreach ($element->getElementsByTagNameNS(Constants::NS_SAMLP, 'NameIDPolicy') as $policy) {
            if ($policy->parentNode === $element
                && $policy->getAttribute('Format') === Constants::NAMEID_TRANSIENT
                && in_array($policy->getAttribute('AllowCreate'), ['true', '1'], true)
            ) {
                $policy->removeAttribute('AllowCreate');
            }
        }

        return self::fromElement($element);
    }

    private static function loadDocumentElement(string $decodedSamlRequest): Element
    {
        if ($decodedSamlRequest === '') {
            throw new InvalidArgumentException(
                'Could not create ReceivedAuthnRequest: expected a non-empty string, received an empty string'
            );
        }

        // additional security against XXE Processing vulnerability
        $document = DOMDocumentFactory::fromString($decodedSamlRequest);

        if (!$document->documentElement instanceof Element) {
            throw new RuntimeException('The SAML message can not be read from the document');
        }

        return $document->documentElement;
    }

    private static function fromElement(Element $element): SAML2AuthnRequest
    {
        $authnRequest = MessageFactory::fromXML($element);

        if (!$authnRequest instanceof SAML2AuthnRequest) {
            throw new RuntimeException(sprintf(
                'The received request is not an AuthnRequest, "%s" received instead',
                $authnRequest::class
            ));
        }

        return $authnRequest;
    }
}
