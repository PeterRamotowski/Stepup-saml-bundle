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

use DateTimeZone;
use Dom\Element;
use Dom\XMLDocument;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Type\SAMLDateTimeValue;
use SimpleSAML\SAML2\XML\samlp\AuthnRequest as SAML2AuthnRequest;
use SimpleSAML\SAML2\XML\samlp\Extensions as SAML2Extensions;
use SimpleSAML\XMLSchema\Type\IDValue;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;
use Surfnet\SamlBundle\Exception\RuntimeException;

/**
 * saml2 v7 AuthnRequests are immutable; the bundle's setters replace the request with a modified copy.
 *
 * @internal
 */
final class AuthnRequestRebuilder
{
    private const array PARAMETERS = [
        'id', 'issueInstant', 'requestedAuthnContext', 'subject', 'nameIdPolicy', 'conditions', 'forceAuthn',
        'isPassive', 'assertionConsumerServiceURL', 'assertionConsumerServiceIndex', 'protocolBinding',
        'attributeConsumingServiceIndex', 'providerName', 'issuer', 'destination', 'consent', 'extensions', 'scoping',
    ];

    /**
     * @param array<string, mixed> $changes Constructor arguments to replace, by parameter name.
     */
    public static function with(SAML2AuthnRequest $request, array $changes): SAML2AuthnRequest
    {
        $unknown = array_diff_key($changes, array_flip(self::PARAMETERS));
        if ($unknown !== []) {
            throw new InvalidArgumentException(sprintf('Unknown AuthnRequest parameters: %s', implode(', ', array_keys($unknown))));
        }

        $extensions = $request->getExtensions();

        return new SAML2AuthnRequest(
            id: self::pick($changes, 'id', $request->getId()),
            issueInstant: self::pick($changes, 'issueInstant', $request->getIssueInstant()),
            requestedAuthnContext: self::pick($changes, 'requestedAuthnContext', $request->getRequestedAuthnContext()),
            subject: self::pick($changes, 'subject', $request->getSubject()),
            nameIdPolicy: self::pick($changes, 'nameIdPolicy', $request->getNameIdPolicy()),
            conditions: self::pick($changes, 'conditions', $request->getConditions()),
            forceAuthn: self::pick($changes, 'forceAuthn', $request->getForceAuthn()),
            isPassive: self::pick($changes, 'isPassive', $request->getIsPassive()),
            assertionConsumerServiceURL: self::pick(
                $changes,
                'assertionConsumerServiceURL',
                $request->getAssertionConsumerServiceURL()
            ),
            assertionConsumerServiceIndex: self::pick(
                $changes,
                'assertionConsumerServiceIndex',
                $request->getAssertionConsumerServiceIndex()
            ),
            protocolBinding: self::pick($changes, 'protocolBinding', $request->getProtocolBinding()),
            attributeConsumingServiceIndex: self::pick(
                $changes,
                'attributeConsumingServiceIndex',
                $request->getAttributeConsumingServiceIndex()
            ),
            providerName: self::pick($changes, 'providerName', $request->getProviderName()),
            issuer: self::pick($changes, 'issuer', $request->getIssuer()),
            destination: self::pick($changes, 'destination', $request->getDestination()),
            consent: self::pick($changes, 'consent', $request->getConsent()),
            extensions: self::pick(
                $changes,
                'extensions',
                $extensions instanceof SAML2Extensions ? $extensions : null
            ),
            scoping: self::pick($changes, 'scoping', $request->getScoping()),
        );
    }

    /**
     * @template T
     * @param array<string, mixed> $changes
     * @param T $current
     * @return T
     */
    private static function pick(array $changes, string $name, mixed $current): mixed
    {
        return array_key_exists($name, $changes) ? $changes[$name] : $current;
    }

    public static function newId(): IDValue
    {
        return IDValue::fromString('_' . bin2hex(random_bytes(30)));
    }

    public static function now(): SAMLDateTimeValue
    {
        return SAMLDateTimeValue::fromDateTime(
            ContainerSingleton::getInstance()->getClock()->now()->setTimezone(new DateTimeZone('UTC'))
        );
    }

    public static function serialize(Element $element): string
    {
        $document = $element->ownerDocument;
        $xml = $document instanceof XMLDocument ? $document->saveXml() : false;
        if (!is_string($xml)) {
            throw new RuntimeException('Could not serialize the SAML message');
        }

        return $xml;
    }
}
