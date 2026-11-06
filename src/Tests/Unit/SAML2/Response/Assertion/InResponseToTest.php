<?php declare(strict_types=1);

/**
 * Copyright 2014 SURFnet bv
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

namespace Surfnet\SamlBundle\Tests\Unit\SAML2\Response\Assertion;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Compat\MockContainer;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\XML\DOMDocumentFactory;
use Surfnet\SamlBundle\SAML2\Response\Assertion\InResponseTo;
use Surfnet\SamlBundle\Tests\TestAssertions;

class InResponseToTest extends TestCase
{

    #[Test]
    #[DataProvider('provideAssertionsWithoutInResponseTo')]
    #[Group('saml2-response')]
    #[Group('saml2')]
    public function assertions_without_in_response_to_are_tested_as_if_in_response_to_is_null(Assertion $assertion): void
    {
        $this->assertTrue(InResponseTo::assertEquals($assertion, null));
        $this->assertFalse(InResponseTo::assertEquals($assertion, 'some not-null-value'));
    }

    #[Test]
    #[Group('saml2-response')]
    #[Group('saml2')]
    public function in_reponse_to_equality_is_strictly_checked(): void
    {
        $assertion = TestAssertions::create(inResponseTo: '_1');

        $this->assertTrue(InResponseTo::assertEquals($assertion, '_1'));
        $this->assertFalse(InResponseTo::assertEquals($assertion, 1));
    }

    public static function provideAssertionsWithoutInResponseTo(): array
    {
        ContainerSingleton::setContainer(new MockContainer());

        $assertionWithSubject = static fn (string $subject): Assertion => Assertion::fromXML(
            DOMDocumentFactory::fromString(
                '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a" Version="2.0"'
                . ' IssueInstant="2026-11-04T12:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer>'
                . '<saml:Subject><saml:NameID>user</saml:NameID>' . $subject . '</saml:Subject></saml:Assertion>'
            )->documentElement
        );

        return [
            'No Subject Confirmation'      => [$assertionWithSubject('')],
            'No Subject Confirmation Data' => [TestAssertions::create(nameId: 'user')],
            'Empty In Reponse To'          => [$assertionWithSubject(
                '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
                . '<saml:SubjectConfirmationData/></saml:SubjectConfirmation>'
            )],
        ];
    }
}
