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

namespace Surfnet\SamlBundle\Tests;

use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\XML\DOMDocumentFactory;

/**
 * Builds real saml2 v7 assertions for tests; v7 assertions are final and cannot be mocked.
 */
final class TestAssertions
{
    /**
     * @param array<string, list<string>> $attributes
     */
    public static function create(
        array $attributes = [],
        ?string $nameId = null,
        ?string $inResponseTo = null,
        string $issuer = 'https://idp.example.com/metadata',
    ): Assertion {
        // v7 requires a Subject on every assertion that carries attributes or no statements at all
        $confirmationData = $inResponseTo === null
            ? ''
            : sprintf('<saml:SubjectConfirmationData InResponseTo="%s"/>', self::escape($inResponseTo));
        $subject = sprintf(
            '<saml:Subject>%s<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">%s'
            . '</saml:SubjectConfirmation></saml:Subject>',
            $nameId === null ? '' : sprintf('<saml:NameID>%s</saml:NameID>', self::escape($nameId)),
            $confirmationData
        );

        $statement = '';
        if ($attributes !== []) {
            $statement = '<saml:AttributeStatement>';
            foreach ($attributes as $name => $values) {
                $statement .= sprintf('<saml:Attribute Name="%s">', self::escape($name));
                foreach ($values as $value) {
                    $statement .= sprintf('<saml:AttributeValue>%s</saml:AttributeValue>', self::escape($value));
                }
                $statement .= '</saml:Attribute>';
            }
            $statement .= '</saml:AttributeStatement>';
        }

        $xml = sprintf(
            '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_%s" Version="2.0"'
            . ' IssueInstant="2026-11-04T12:00:00Z"><saml:Issuer>%s</saml:Issuer>%s%s</saml:Assertion>',
            bin2hex(random_bytes(16)),
            self::escape($issuer),
            $subject,
            $statement
        );

        return Assertion::fromXML(DOMDocumentFactory::fromString($xml)->documentElement);
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES);
    }
}
