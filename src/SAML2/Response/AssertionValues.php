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

namespace Surfnet\SamlBundle\SAML2\Response;

use Dom\XMLDocument;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\NameID;
use SimpleSAML\SAML2\XML\saml\NameIDType;
use SimpleSAML\XML\AbstractElement;
use SimpleSAML\XMLSchema\Type\Interface\ValueTypeInterface;

/**
 * Reads the values the bundle's 4.x API exposed as flat accessors from a saml2 v7 assertion.
 */
final class AssertionValues
{
    public static function nameId(Assertion $assertion): ?string
    {
        $identifier = $assertion->getSubject()?->getIdentifier();

        return $identifier instanceof NameID ? trim($identifier->getContent()->getValue()) : null;
    }

    public static function issuer(Assertion $assertion): string
    {
        return trim($assertion->getIssuer()->getContent()->getValue());
    }

    /**
     * The InResponseTo of the first SubjectConfirmation, as the 4.x bundle used it for request correlation.
     */
    public static function inResponseTo(Assertion $assertion): ?string
    {
        $confirmations = $assertion->getSubject()?->getSubjectConfirmation() ?? [];
        if ($confirmations === []) {
            return null;
        }

        return $confirmations[0]->getSubjectConfirmationData()?->getInResponseTo()?->getValue();
    }

    /**
     * Attribute values keyed by attribute name; values of equally named attributes are merged.
     *
     * @return array<string, list<string>>
     */
    public static function attributes(Assertion $assertion): array
    {
        $attributes = [];
        foreach ($assertion->getAttributeStatements() as $statement) {
            foreach ($statement->getAttributes() as $attribute) {
                $name = $attribute->getName()->getValue();
                $attributes[$name] ??= [];
                foreach ($attribute->getAttributeValues() as $attributeValue) {
                    $attributes[$name][] = self::toString($attributeValue->getValue());
                }
            }
        }

        return $attributes;
    }

    private static function toString(ValueTypeInterface|AbstractElement|null $value): string
    {
        if ($value === null) {
            return '';
        }
        if ($value instanceof ValueTypeInterface) {
            return trim($value->getValue());
        }
        if ($value instanceof NameIDType) {
            return trim($value->getContent()->getValue());
        }

        $element = $value->toXML();
        $document = $element->ownerDocument;

        return $document instanceof XMLDocument ? (string) $document->saveXml($element) : '';
    }
}
