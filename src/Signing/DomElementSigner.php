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

namespace Surfnet\SamlBundle\Signing;

use Dom\Element;
use Dom\Node;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\XMLSchema\Type\IDValue;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface;
use SimpleSAML\XMLSecurity\Constants as C;
use SimpleSAML\XMLSecurity\XML\CanonicalizableElementTrait;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;
use SimpleSAML\XMLSecurity\XML\ds\Signature;
use SimpleSAML\XMLSecurity\XML\SignableElementTrait;
use Surfnet\SamlBundle\Exception\RuntimeException;

/**
 * Adds an enveloped XML signature to a DOM element that has no xml-security element class, such as rendered metadata.
 *
 * @internal
 */
final class DomElementSigner
{
    use CanonicalizableElementTrait;
    use SignableElementTrait;

    private function __construct(private readonly Element $element)
    {
    }

    public static function signEnveloped(
        Element $element,
        SignatureAlgorithmInterface $signer,
        KeyInfo $keyInfo,
        ?Node $insertBefore = null,
    ): void {
        // Like xmlseclibs did, reference the element by ID; SAML verifiers reject a reference without URI.
        if (!$element->hasAttribute('ID')) {
            $element->setAttribute('ID', '_' . bin2hex(random_bytes(20)));
        }

        $instance = new self($element);
        $instance->sign($signer, C::C14N_EXCLUSIVE_WITHOUT_COMMENTS, $keyInfo);
        // doSign() only returns a canonical copy; the signature is attached to the original element below.
        // PHPMD cannot parse the (void) cast yet, so the copy is released explicitly.
        $canonicalCopy = $instance->doSign($element);
        unset($canonicalCopy);

        if (!$instance->signature instanceof Signature) {
            throw new RuntimeException('Signing did not produce a signature');
        }

        $signatureElement = $instance->signature->toXML($element);
        if ($insertBefore !== null && $insertBefore !== $signatureElement) {
            $element->insertBefore($signatureElement, $insertBefore);
        }
    }

    public function getId(): ?IDValue
    {
        $id = $this->element->getAttribute('ID');

        // xml-security documents the return type as the removed SimpleSAML\XML\Type\IDValue.
        /** @phpstan-ignore return.type */
        return $id === null || $id === '' ? null : IDValue::fromString($id);
    }

    public function getBlacklistedAlgorithms(): ?array
    {
        return ContainerSingleton::getInstance()->getBlacklistedEncryptionAlgorithms();
    }

    protected function getOriginalXML(): Element
    {
        return $this->element;
    }

    protected function setSignature(Signature $signature): void
    {
        $this->signature = $signature;
    }
}
