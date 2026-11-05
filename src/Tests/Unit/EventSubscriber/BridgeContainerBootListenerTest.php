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

namespace Surfnet\SamlBundle\Tests\Unit\EventSubscriber;

use Composer\Autoload\ClassLoader;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Surfnet\SamlBundle\EventSubscriber\BridgeContainerBootListener;
use Symfony\Component\Console\ConsoleEvents;
use Symfony\Component\HttpKernel\KernelEvents;

class BridgeContainerBootListenerTest extends TestCase
{
    #[Test]
    public function installed_console_events_are_registered(): void
    {
        $events = BridgeContainerBootListener::getSubscribedEvents();
        self::assertSame(['onKernelRequest', 256], $events[KernelEvents::REQUEST]);
        self::assertSame(['onKernelRequest', 256], $events[ConsoleEvents::COMMAND]);
    }

    #[Test]
    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function http_events_work_without_symfony_console(): void
    {
        $loaders = ClassLoader::getRegisteredLoaders();
        foreach ($loaders as $loader) {
            $loader->unregister();
        }
        spl_autoload_register(static function (string $class) use ($loaders): void {
            if (str_starts_with($class, 'Symfony\\Component\\Console\\')) {
                return;
            }
            foreach ($loaders as $loader) {
                $loader->loadClass($class);
            }
        });

        self::assertFalse(class_exists(ConsoleEvents::class));
        self::assertSame([KernelEvents::REQUEST => ['onKernelRequest', 256]], BridgeContainerBootListener::getSubscribedEvents());
    }
}
