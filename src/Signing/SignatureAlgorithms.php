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

namespace Surfnet\SamlBundle\Signing;

use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;

/**
 * @internal
 */
final class SignatureAlgorithms
{
    /**
     * A factory that honours the algorithm blacklist of the installed saml2 container.
     */
    public static function factory(): SignatureAlgorithmFactory
    {
        return new SignatureAlgorithmFactory(
            ContainerSingleton::getInstance()->getBlacklistedEncryptionAlgorithms()
                ?? SignatureAlgorithmFactory::DEFAULT_BLACKLIST
        );
    }
}
