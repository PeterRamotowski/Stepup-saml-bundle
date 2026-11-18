<?php declare(strict_types=1);

/**
 * Copyright 2021 SURFnet B.V.
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

use Dom\Element;
use Dom\XMLDocument;
use DOMDocument;
use DOMElement;
use SimpleSAML\SAML2\XML\samlp\Extensions as SAML2Extensions;
use SimpleSAML\XML\Chunk as SAML2Chunk;
use SimpleSAML\XML\DOMDocumentFactory;
use Surfnet\SamlBundle\Exception\RuntimeException;
use Surfnet\SamlBundle\SAML2\AuthnRequestRebuilder;

/**
 * The bundle's extension chunks keep their legacy DOMElement API; values are converted at the saml2 v7 boundary.
 */
trait ExtensionsMapperTrait
{
    private Extensions $extensions;

    private function loadExtensionsFromSaml2AuthNRequest(): void
    {
        $this->extensions = new Extensions();
        $rawExtensions = $this->request->getExtensions();
        if (!$rawExtensions instanceof SAML2Extensions) {
            return;
        }

        foreach ($rawExtensions->getElements() as $rawElement) {
            $value = self::toLegacyElement($rawElement->toXML());

            match (true) {
                $value->localName === 'UserAttributes' => $this->extensions->addChunk(
                    new GsspUserAttributesChunk($value)
                ),
                $value->localName === 'UIInfo'
                    && $value->namespaceURI === MduiChunk::MDUI_NAMESPACE => $this->extensions->addChunk(
                        new MduiChunk($value)
                    ),
                default => $this->extensions->addChunk(
                    new Chunk((string) $value->localName, (string) $value->namespaceURI, $value)
                ),
            };
        }
    }

    public function getExtensions(): Extensions
    {
        if (!isset($this->extensions)) {
            $this->extensions = new Extensions();
        }
        return $this->extensions;
    }

    public function setExtensions(Extensions $extensions): void
    {
        $this->extensions = $extensions;
        $samlExt = [];
        foreach ($this->extensions->getChunks() as $chunk) {
            $samlExt[] = new SAML2Chunk(self::toModernElement($chunk->getValue()));
        }
        $this->request = AuthnRequestRebuilder::with($this->request, [
            'extensions' => $samlExt === [] ? null : new SAML2Extensions($samlExt),
        ]);
    }

    private static function toModernElement(DOMElement $element): Element
    {
        $xml = $element->ownerDocument?->saveXML($element);
        $modern = is_string($xml) && $xml !== '' ? DOMDocumentFactory::fromString($xml)->documentElement : null;
        if (!$modern instanceof Element) {
            throw new RuntimeException('Could not convert the extension element');
        }

        return $modern;
    }

    private static function toLegacyElement(Element $element): DOMElement
    {
        $document = $element->ownerDocument;
        $xml = $document instanceof XMLDocument ? $document->saveXml($element) : false;
        $legacy = new DOMDocument('1.0', 'UTF-8');
        if (!is_string($xml) || !$legacy->loadXML($xml) || !$legacy->documentElement instanceof DOMElement) {
            throw new RuntimeException('Could not convert the extension element');
        }

        return $legacy->documentElement;
    }
}
