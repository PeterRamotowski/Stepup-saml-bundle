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

namespace Surfnet\SamlBundle\PrivateKeyAgent;

use SensitiveParameter;
use SimpleSAML\XMLSecurity\Backend\PrivateKeyAgent\TokenProvider;
use SimpleSAML\XMLSecurity\Exception\MissingTokenException;

/**
 * Bearer tokens per agent key name, from the bundle configuration.
 */
final readonly class ConfiguredTokenProvider implements TokenProvider
{
    /**
     * @param array<string, string> $tokens Token by agent key name
     */
    public function __construct(
        #[SensitiveParameter]
        private array $tokens,
    ) {
    }

    public function getToken(string $keyName): string
    {
        $token = $this->tokens[$keyName] ?? '';
        if ($token === '') {
            throw new MissingTokenException(sprintf('No bearer token is configured for agent key "%s".', $keyName));
        }

        return $token;
    }
}
