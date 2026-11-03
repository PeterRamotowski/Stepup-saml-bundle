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

namespace Surfnet\SamlBundle\Tests\Unit\SAML2;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SimpleSAML\SAML2\Exception\ProtocolViolationException;
use Surfnet\SamlBundle\SAML2\AuthnRequestParser;

class AuthnRequestParserTest extends TestCase
{
    private const REQUEST = <<<XML
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_2b0226190ca1c22de6f66e85f5c95158" Version="2.0" IssueInstant="2014-09-22T13:42:00Z">
  <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
  <samlp:NameIDPolicy Format="%s" AllowCreate="true"/>
</samlp:AuthnRequest>
XML;

    private const TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
    private const PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    #[Test]
    public function strict_parsing_rejects_allow_create_with_a_transient_format(): void
    {
        $this->expectException(ProtocolViolationException::class);
        AuthnRequestParser::parse(sprintf(self::REQUEST, self::TRANSIENT));
    }

    #[Test]
    public function redirect_binding_parsing_drops_allow_create_with_a_transient_format(): void
    {
        $request = AuthnRequestParser::parseFromHttpRedirectBinding(sprintf(self::REQUEST, self::TRANSIENT));

        $this->assertSame(self::TRANSIENT, $request->getNameIdPolicy()?->getFormat()?->getValue());
        $this->assertNull($request->getNameIdPolicy()?->getAllowCreate());
    }

    #[Test]
    public function redirect_binding_parsing_keeps_allow_create_with_other_formats(): void
    {
        $request = AuthnRequestParser::parseFromHttpRedirectBinding(sprintf(self::REQUEST, self::PERSISTENT));

        $this->assertTrue($request->getNameIdPolicy()?->getAllowCreate()?->toBoolean());
    }
}
