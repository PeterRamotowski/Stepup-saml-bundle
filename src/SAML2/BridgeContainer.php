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

namespace Surfnet\SamlBundle\SAML2;

use BadMethodCallException;
use Dom\Element;
use DOMElement;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use SimpleSAML\SAML2\Compat\AbstractContainer;
use SimpleSAML\XMLSecurity\Alg\Encryption\EncryptionAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\KeyTransportAlgorithmFactory;
use SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmFactory;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;

/**
 * Container that is required so that we can make the SAML2 lib work.
 * This container is set as the container in the SurfnetSamlBundle::boot() method
 */
class BridgeContainer extends AbstractContainer
{
    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly ClockInterface $clock,
    ) {
        // The parent default nests the factory lists, which the factories' flat in_array check never matches.
        $this->blacklistedEncryptionAlgorithms = array_values(array_unique(array_merge(
            EncryptionAlgorithmFactory::DEFAULT_BLACKLIST,
            KeyTransportAlgorithmFactory::DEFAULT_BLACKLIST,
            SignatureAlgorithmFactory::DEFAULT_BLACKLIST,
        )));
    }

    /**
     * @param string[]|null $algos Algorithm URIs to forbid, or null to use each factory's own default.
     */
    public function setBlacklistedAlgorithms(?array $algos): void
    {
        if ($algos !== null) {
            foreach ($algos as $algo) {
                if (!is_string($algo)) {
                    throw new InvalidArgumentException('Blacklisted algorithms must be a flat list of algorithm URIs.');
                }
            }
            $algos = array_values($algos);
        }

        $this->blacklistedEncryptionAlgorithms = $algos;
    }

    public function getClock(): ClockInterface
    {
        return $this->clock;
    }

    /**
     * @return LoggerInterface
     */
    public function getLogger(): LoggerInterface
    {
        return $this->logger;
    }

    /**
     * Generate a random identifier for identifying SAML2 documents.
     */
    public function generateId(): string
    {
        return '_' . bin2hex(openssl_random_pseudo_bytes(30));
    }

    public function debugMessage($message, string $type): void
    {
        if ($message instanceof Element) {
            $message = $message->ownerDocument->saveXml($message);
        } elseif ($message instanceof DOMElement) {
            $message = $message->ownerDocument->saveXML($message);
        }

        if (!is_string($message)) {
            throw new InvalidArgumentException("Debug message error: could not convert message to string.");
        }

        $this->logger->debug($message, ['type' => $type]);
    }

    /** @throws BadMethodCallException */
    public function getPOSTRedirectURL(string $url, array $data = []): string
    {
        $this->notSupported(__METHOD__);
        return '';
    }

    /** @throws BadMethodCallException */
    public function getTempDir(): string
    {
        $this->notSupported(__METHOD__);
        return '';
    }

    public function writeFile(string $filename, string $data, ?int $mode = null): void
    {
        $this->notSupported(__METHOD__);
    }

    public function notSupported(string $method): void
    {
        throw new BadMethodCallException(sprintf(
            "%s:%s may not be called in the Surfnet\\SamlBundle",
            self::class,
            $method
        ));
    }
}
