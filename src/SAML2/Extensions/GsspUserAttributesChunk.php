<?php
/**
 * Copyright 2025 SURFnet bv
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

namespace Surfnet\SamlBundle\SAML2\Extensions;

use DOMDocument;
use DOMElement;
use DOMNode;
use RuntimeException;

class GsspUserAttributesChunk extends Chunk
{
    private const SAML_ASSERTION_NAMESPACE = 'urn:oasis:names:tc:SAML:2.0:assertion';

    public function __construct(?DOMElement $value = null)
    {
        $doc = new DOMDocument("1.0", "UTF-8");
        $root = $doc->createElementNS('urn:mace:surf.nl:stepup:gssp-extensions', 'gssp:UserAttributes');
        $root->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance');
        $root->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:xs', 'http://www.w3.org/2001/XMLSchema');

        if ($value && $value->hasChildNodes()) {
            foreach ($value->childNodes as $child) {
                $root->appendChild($doc->importNode($child->cloneNode(true), true));
            }
        }

        $doc->appendChild($doc->importNode($root, true));
        parent::__construct('UserAttributes', 'urn:mace:surf.nl:stepup:gssp-extensions', $doc->documentElement);
    }

    public function getAttributeValue(string $attributeName): ?string
    {
        foreach ($this->getValue()->childNodes as $attribute) {
            if (!self::isSamlAssertionElement($attribute, 'Attribute')
                || $attribute->getAttribute('Name') !== $attributeName
            ) {
                continue;
            }

            foreach ($attribute->childNodes as $value) {
                if (self::isSamlAssertionElement($value, 'AttributeValue')) {
                    return $value->textContent;
                }
            }
        }

        return null;
    }

    /**
     * @phpstan-assert-if-true DOMElement $node
     */
    private static function isSamlAssertionElement(DOMNode $node, string $localName): bool
    {
        return $node instanceof DOMElement
            && $node->namespaceURI === self::SAML_ASSERTION_NAMESPACE
            && $node->localName === $localName;
    }

    public function addAttribute(string $name, string $format, string $value): void
    {
        $doc = new DOMDocument("1.0", "UTF-8");
        $attrib = $doc->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Attribute');
        $attrib->setAttribute('NameFormat', $format);
        $attrib->setAttribute('Name', $name);

        $attribValue = $doc->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AttributeValue', $value);
        $attribValue->setAttribute('xsi:type', 'xs:string');

        $attrib->appendChild($attribValue);
        $doc->appendChild($attrib);
        $this->append($doc->documentElement);
    }

    public function toXML(): string
    {
        $doc = $this->getValue()->ownerDocument;
        if ($doc === null) {
            throw new RuntimeException('DOMElement has no ownerDocument');
        }
        $xml = $doc->saveXML();
        if ($xml === false) {
            throw new RuntimeException('Failed to serialize XML document');
        }
        return $xml;
    }

    public static function fromXML(string $xmlString): GsspUserAttributesChunk
    {
        $doc = new DOMDocument();
        $doc->loadXML($xmlString);
        return new self($doc->documentElement);
    }
}
