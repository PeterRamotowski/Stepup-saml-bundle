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

use SimpleSAML\SAML2\Constants;
use SimpleSAML\SAML2\Type\EntityIDValue;
use SimpleSAML\SAML2\Type\SAMLAnyURIValue;
use SimpleSAML\SAML2\Type\SAMLStringValue;
use SimpleSAML\SAML2\XML\saml\AuthnContextClassRef;
use SimpleSAML\SAML2\XML\saml\NameID;
use SimpleSAML\SAML2\XML\saml\Subject;
use SimpleSAML\SAML2\XML\samlp\RequestedAuthnContext;
use SimpleSAML\SAML2\XML\samlp\RequesterID;
use SimpleSAML\SAML2\XML\samlp\Scoping;
use SimpleSAML\XMLSchema\Type\NonNegativeIntegerValue;

/**
 * Bundle-facing accessors shared by AuthnRequest and ReceivedAuthnRequest, mapped onto the saml2 v7 element model.
 *
 * @internal
 */
trait AuthnRequestAccessorsTrait
{
    public function getAuthenticationContextClassRef(): ?string
    {
        foreach ($this->request->getRequestedAuthnContext()?->getRequestedAuthnContexts() ?? [] as $context) {
            if ($context instanceof AuthnContextClassRef) {
                return $context->getContent()->getValue() ?: null;
            }
        }

        return null;
    }

    public function setAuthenticationContextClassRef($authnClassRef): void
    {
        $this->request = AuthnRequestRebuilder::with($this->request, [
            'requestedAuthnContext' => new RequestedAuthnContext([
                new AuthnContextClassRef(SAMLAnyURIValue::fromString((string) $authnClassRef)),
            ]),
        ]);
    }

    public function getNameIdFormat(): ?string
    {
        return $this->getRequestNameId()?->getFormat()?->getValue();
    }

    public function setSubject(string $nameId, ?string $format = null): void
    {
        $this->request = AuthnRequestRebuilder::with($this->request, [
            'subject' => new Subject(
                new NameID(
                    SAMLStringValue::fromString($nameId),
                    Format: SAMLAnyURIValue::fromString($format ?: Constants::NAMEID_UNSPECIFIED),
                ),
                $this->request->getSubject()?->getSubjectConfirmation() ?? [],
            ),
        ]);
    }

    public function getRequestId(): string
    {
        return $this->request->getId()->getValue();
    }

    public function isPassive(): bool
    {
        return $this->request->getIsPassive()?->toBoolean() ?? false;
    }

    public function isForceAuthn(): bool
    {
        return $this->request->getForceAuthn()?->toBoolean() ?? false;
    }

    public function setScoping(array $requesterIds, int $proxyCount = 10): void
    {
        $this->request = AuthnRequestRebuilder::with($this->request, [
            'scoping' => new Scoping(
                NonNegativeIntegerValue::fromInteger($proxyCount),
                $this->request->getScoping()?->getIDPList(),
                array_map(
                    static fn (string $id): RequesterID => new RequesterID(EntityIDValue::fromString($id)),
                    array_values($requesterIds)
                ),
            ),
        ]);
    }

    public function getUnsignedXML(): string
    {
        // A fresh copy carries no signature, so toXML() serialises the unsigned message.
        return AuthnRequestRebuilder::serialize(AuthnRequestRebuilder::with($this->request, [])->toXML());
    }

    private function getRequestNameId(): ?NameID
    {
        $identifier = $this->request->getSubject()?->getIdentifier();

        return $identifier instanceof NameID ? $identifier : null;
    }
}
