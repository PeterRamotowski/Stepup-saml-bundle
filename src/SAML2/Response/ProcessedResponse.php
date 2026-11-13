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

use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\samlp\Response;

/**
 * The verified and validated result of ResponseProcessor::processResponse().
 *
 * The Response envelope is only available when its signature was verified; an unsigned envelope is never returned, so
 * its fields cannot be mistaken for trusted data. The envelope's assertions are as received: an encrypted assertion
 * stays encrypted there, while getAssertion() returns the decrypted, verified and validated assertion.
 */
final readonly class ProcessedResponse
{
    public function __construct(
        private ?Response $verifiedResponse,
        private Assertion $assertion,
    ) {
    }

    /**
     * The Response as covered by its verified signature, or null when the Response was not signed.
     */
    public function getVerifiedResponse(): ?Response
    {
        return $this->verifiedResponse;
    }

    public function getAssertion(): Assertion
    {
        return $this->assertion;
    }
}
