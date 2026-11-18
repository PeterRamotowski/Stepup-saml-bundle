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

namespace Surfnet\SamlBundle\SAML2\Response\Validation;

use DateInterval;
use SimpleSAML\SAML2\Assertion\Validation\AssertionConstraintValidator;
use SimpleSAML\SAML2\Assertion\Validation\Result;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\XML\saml\Assertion;

/**
 * Replaces saml2 7.0.0-rc4's SessionNotOnOrAfter, which compares a value object with a DateTime (never true)
 * and fails on assertions without an AuthnStatement.
 */
final class SessionNotOnOrAfter implements AssertionConstraintValidator
{
    public function validate(Assertion $assertion, Result $result): void
    {
        $limit = ContainerSingleton::getInstance()->getClock()->now()->sub(new DateInterval('PT60S'));

        foreach ($assertion->getAuthnStatements() as $authnStatement) {
            $sessionNotOnOrAfter = $authnStatement->getSessionNotOnOrAfter()?->toDateTime();
            if ($sessionNotOnOrAfter !== null && $sessionNotOnOrAfter <= $limit) {
                $result->addError(
                    'Received an assertion with a session that has expired. Check clock synchronization on IdP and SP.'
                );

                return;
            }
        }
    }
}
