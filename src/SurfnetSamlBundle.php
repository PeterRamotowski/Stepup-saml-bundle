<?php

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

namespace Surfnet\SamlBundle;

use SimpleSAML\SAML2\Compat\ContainerSingleton;
use Surfnet\SamlBundle\DependencyInjection\Compiler\SamlAttributeRegistrationCompilerPass;
use Surfnet\SamlBundle\DependencyInjection\Compiler\SpRepositoryAliasCompilerPass;
use Surfnet\SamlBundle\DependencyInjection\SurfnetSamlExtension;
use Surfnet\SamlBundle\PrivateKeyAgent\AlgorithmRegistrar;
use Surfnet\SamlBundle\SAML2\BridgeContainer;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

class SurfnetSamlBundle extends AbstractBundle
{
    private ?AlgorithmRegistrar $algorithmRegistrar = null;

    public function boot(): void
    {
        parent::boot();

        $bridgeContainer = $this->container?->get('surfnet_saml.saml2.bridge_container');
        if ($bridgeContainer instanceof BridgeContainer) {
            ContainerSingleton::setContainer($bridgeContainer);
        }

        AlgorithmRegistrar::reset();
        if ($this->container?->has('surfnet_saml.private_key_agent.algorithm_registrar')) {
            $registrar = $this->container->get('surfnet_saml.private_key_agent.algorithm_registrar');
            if ($registrar instanceof AlgorithmRegistrar) {
                $registrar->register();
                $this->algorithmRegistrar = $registrar;
            }
        }
    }

    public function shutdown(): void
    {
        $this->algorithmRegistrar?->unregister();
        $this->algorithmRegistrar = null;

        parent::shutdown();
    }

    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        $container->addCompilerPass(new SpRepositoryAliasCompilerPass());
        $container->addCompilerPass(new SamlAttributeRegistrationCompilerPass());
        
        $container->registerExtension(new SurfnetSamlExtension());
    }
}
