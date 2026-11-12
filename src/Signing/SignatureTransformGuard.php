<?php declare(strict_types=1);

/**
 * Copyright 2026 SURFnet bv
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

use Dom\Document;
use Dom\Element;
use DOMDocument;
use DOMElement;
use Surfnet\SamlBundle\Http\Exception\SignatureValidationFailedException;

/**
 * Rejects XML-DSig `<ds:Transform>` algorithms that are not needed for SAML 2.0 signature
 * verification, before the document reaches signature processing.
 *
 * Introduced for GHSA-5cjr-mxj5-wmrx in simplesamlphp/saml2 <=4.20.2: an attacker-controlled
 * `<ds:Transform Algorithm="...xpath-19991116">` executed an attacker-supplied XPath expression
 * during canonicalization. simplesamlphp/xml-security 3.x, used with saml2 v7, still evaluates
 * XPath transforms (bounded by MAX_TRANSFORMS and MAX_XPATH_NAMESPACES), and SAML 2.0 never needs
 * them, so the guard is kept: it restricts transforms to the algorithms the SAML 2.0 Core
 * specification uses.
 *
 * Accepts a complete document or a signature element. Response and Assertion signatures must both be
 * checked, including Assertion signatures that only become visible after decryption.
 */
final class SignatureTransformGuard
{
    /**
     * The only Transform algorithms simplesamlphp/saml2's response/assertion signature
     * verification legitimately needs to process. Anything else is rejected outright.
     */
    private const ALLOWED_TRANSFORM_ALGORITHMS = [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
        'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
        'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
        'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
    ];

    public static function assertNoForbiddenTransforms(DOMDocument|Document|DOMElement|Element $document): void
    {
        foreach ($document->getElementsByTagNameNS('*', 'Transform') as $node) {
            if (!$node->hasAttribute('Algorithm')) {
                continue;
            }

            $algorithm = $node->getAttribute('Algorithm');
            if (in_array($algorithm, self::ALLOWED_TRANSFORM_ALGORITHMS, true)) {
                continue;
            }

            throw new SignatureValidationFailedException(sprintf(
                'Rejected SAML message: contains a forbidden XML signature Transform algorithm "%s"'
                . ' (see GHSA-5cjr-mxj5-wmrx)',
                $algorithm
            ));
        }
    }
}
