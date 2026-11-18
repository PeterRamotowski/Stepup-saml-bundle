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

namespace Surfnet\SamlBundle\Tests\Unit\Security;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Surfnet\SamlBundle\Monolog\SamlAuthenticationLogger;
use Surfnet\SamlBundle\Security\Authentication\Handler\ProcessSamlAuthenticationHandler;
use Surfnet\SamlBundle\Security\Authentication\SamlInteractionProvider;
use Surfnet\SamlBundle\Tests\TestAssertions;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class ProcessSamlAuthenticationHandlerTest extends TestCase
{
    public static function correlations(): iterable
    {
        yield 'matching pending request' => ['_pending', '_pending', true];
        yield 'missing confirmation InResponseTo' => [null, '_pending', false];
        yield 'mismatched confirmation InResponseTo' => ['_other', '_pending', false];
        yield 'missing pending request' => ['_pending', '', false];
        yield 'no confirmation and no pending request' => [null, '', false];
    }

    #[Test]
    #[DataProvider('correlations')]
    public function only_an_assertion_for_the_pending_request_is_accepted(
        ?string $inResponseTo,
        string $pending,
        bool $accepted,
    ): void {
        $assertion = TestAssertions::create(nameId: 'user', inResponseTo: $inResponseTo);
        $provider = $this->createMock(SamlInteractionProvider::class);
        $provider->expects($this->once())->method('processSamlResponse')->willReturn($assertion);
        $handler = new ProcessSamlAuthenticationHandler(
            $provider,
            FakeAuthencationStateHandler::createWithRequestId($pending),
            new SamlAuthenticationLogger(new NullLogger())
        );
        if (!$accepted) {
            $this->expectException(AuthenticationException::class);
        }
        $result = $handler->process(new Request());
        $this->assertSame($assertion, $result);
    }
}
