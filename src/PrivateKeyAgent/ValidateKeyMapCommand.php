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

use Closure;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'surfnet:saml:validate-private-key-agent', description: 'Validate Private Key Agent certificate mappings')]
final class ValidateKeyMapCommand extends Command
{
    /**
     * @param Closure(): KeyMap $keyMap
     */
    public function __construct(private readonly Closure $keyMap)
    {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        ($this->keyMap)();
        $output->writeln('Private Key Agent certificate mappings are valid.');

        return self::SUCCESS;
    }
}
