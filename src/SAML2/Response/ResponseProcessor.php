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

namespace Surfnet\SamlBundle\SAML2\Response;

use Exception;
use Psr\Log\LoggerInterface;
use SimpleSAML\SAML2\Assertion\Exception\InvalidAssertionException;
use SimpleSAML\SAML2\Assertion\Exception\InvalidSubjectConfirmationException;
use SimpleSAML\SAML2\Assertion\Validation\AssertionValidator;
use SimpleSAML\SAML2\Assertion\Validation\ConstraintValidator as Constraint;
use SimpleSAML\SAML2\Assertion\Validation\SubjectConfirmationValidator;
use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\PrivateKeyLoader;
use SimpleSAML\SAML2\Certificate\X509;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Configuration\Destination;
use SimpleSAML\SAML2\Response\Exception\InvalidResponseException;
use SimpleSAML\SAML2\Response\Exception\InvalidSignatureException;
use SimpleSAML\SAML2\Response\Exception\PreconditionNotMetException;
use SimpleSAML\SAML2\Response\Exception\UnsignedResponseException;
use SimpleSAML\SAML2\Response\Validation\PreconditionValidator;
use SimpleSAML\SAML2\XML\saml\Assertion;
use SimpleSAML\SAML2\XML\saml\EncryptedAssertion;
use SimpleSAML\SAML2\XML\saml\EncryptedID;
use SimpleSAML\SAML2\XML\samlp\Response;
use SimpleSAML\XMLSecurity\Alg\KeyTransport\KeyTransportAlgorithmFactory;
use SimpleSAML\XMLSecurity\Key\PrivateKey;
use SimpleSAML\XMLSecurity\XML\SignedElementInterface;
use SimpleSAML\XMLSecurity\XML\xenc\EncryptedKey;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\SAML2\Response\Validation\SessionNotOnOrAfter;
use Surfnet\SamlBundle\Signing\CertificateKeys;
use Surfnet\SamlBundle\Signing\SignatureAlgorithms;

/**
 * Turns a received SAML Response into the single, verified and validated assertion it carries.
 *
 * Replaces saml2's Response\Processor, whose builder hard-wires a private-key decrypter that passes a key where
 * an algorithm is expected, verifies signatures without the algorithm blacklist and keeps using the unverified
 * element afterwards. The order is: preconditions, Response signature, decryption, Assertion signature, validation.
 *
 * @SuppressWarnings("PHPMD.CouplingBetweenObjects")
 */
class ResponseProcessor
{
    public function __construct(
        private readonly KeyLoader $keyLoader,
        private readonly PrivateKeyLoader $privateKeyLoader,
        private readonly LoggerInterface $logger,
    ) {
    }

    /**
     * @throws PreconditionNotMetException when the Response is not a success or not addressed to this SP
     * @throws InvalidResponseException when it cannot be trusted or does not carry exactly one valid assertion
     */
    public function process(
        ServiceProvider $serviceProvider,
        IdentityProvider $identityProvider,
        string $destination,
        Response $response,
    ): Assertion {
        $result = (new PreconditionValidator(new Destination($destination)))->validate($response);
        if (!$result->isValid()) {
            throw PreconditionNotMetException::createFromValidationResult($result);
        }

        $responseIsSigned = $response->isSigned();
        if ($responseIsSigned) {
            $response = $this->verified($response, $identityProvider, Response::class);
        }

        $assertions = $response->getAssertions();
        if (count($assertions) !== 1) {
            throw new InvalidResponseException(sprintf('Expected exactly one assertion, found %d', count($assertions)));
        }

        $assertion = $assertions[0];
        if ($assertion instanceof EncryptedAssertion) {
            $assertion = $this->decrypt($assertion, $serviceProvider, $identityProvider);
        }

        if ($assertion->isSigned()) {
            $assertion = $this->verified($assertion, $identityProvider, Assertion::class);
        } elseif (!$responseIsSigned) {
            throw new UnsignedResponseException('Both the response and the assertion it contains are not signed.');
        }

        $this->validate($assertion, $serviceProvider, $identityProvider, $destination, $response);

        return $assertion;
    }

    /**
     * Returns the element as covered by the signature, never the document it was found in.
     *
     * @template T of SignedElementInterface
     * @param T $element
     * @param class-string<T> $expectedClass
     * @return T
     */
    private function verified(
        SignedElementInterface $element,
        IdentityProvider $identityProvider,
        string $expectedClass,
    ): SignedElementInterface {
        $algorithm = $element->getSignature()?->getSignedInfo()->getSignatureMethod()->getAlgorithm()->getValue();
        $lastException = null;

        foreach (CertificateKeys::extract($this->keyLoader, $identityProvider) as $index => $key) {
            if (!$key instanceof X509) {
                continue;
            }

            try {
                $verified = $element->verify(
                    SignatureAlgorithms::factory()->getAlgorithm((string) $algorithm, CertificateKeys::toPublicKey($key))
                );
                if ($verified instanceof $expectedClass) {
                    return $verified;
                }
            } catch (Exception $exception) {
                $this->logger->debug(sprintf('Signature verification with key #%d failed: %s', $index, $exception->getMessage()));
                $lastException = $exception;
            }
        }

        throw new InvalidSignatureException(
            'The signature could not be verified with any configured certificate of the identity provider',
            0,
            $lastException
        );
    }

    private function decrypt(
        EncryptedAssertion $encryptedAssertion,
        ServiceProvider $serviceProvider,
        IdentityProvider $identityProvider,
    ): Assertion {
        // Only the single-recipient case is supported: xml-security 3.1.0 keeps just the first EncryptedKey of the
        // KeyInfo, saml2 ignores EncryptedKeys next to the EncryptedData, and the key transport loop would call the
        // backend once per key and abort on the first agent error. Count both places so nothing is skipped silently.
        $encryptedKeys = array_merge(
            array_values(array_filter(
                $encryptedAssertion->getEncryptedData()->getKeyInfo()?->getInfo() ?? [],
                static fn (object $info): bool => $info instanceof EncryptedKey
            )),
            $encryptedAssertion->getDecryptionKeys()
        );
        if (count($encryptedKeys) !== 1) {
            throw new InvalidAssertionException(sprintf(
                'Expected exactly one EncryptedKey in the EncryptedAssertion, found %d',
                count($encryptedKeys)
            ));
        }

        $algorithm = $encryptedKeys[0]->getEncryptionMethod()?->getAlgorithm()->getValue();
        if ($algorithm === null) {
            throw new InvalidAssertionException('The EncryptedKey has no EncryptionMethod');
        }

        $factory = new KeyTransportAlgorithmFactory(
            ContainerSingleton::getInstance()->getBlacklistedEncryptionAlgorithms()
                ?? KeyTransportAlgorithmFactory::DEFAULT_BLACKLIST
        );

        $lastException = null;
        foreach ($this->privateKeyLoader->loadDecryptionKeys($identityProvider, $serviceProvider) as $key) {
            if (!$key instanceof PrivateKey) {
                throw new InvalidAssertionException('Only RSA key transport is supported for encrypted assertions');
            }

            try {
                return $encryptedAssertion->decrypt($factory->getAlgorithm($algorithm, $key));
            } catch (Exception $exception) {
                $lastException = $exception;
            }
        }

        throw new InvalidAssertionException('The assertion could not be decrypted', 0, $lastException);
    }

    private function validate(
        Assertion $assertion,
        ServiceProvider $serviceProvider,
        IdentityProvider $identityProvider,
        string $destination,
        Response $response,
    ): void {
        $assertionValidator = new AssertionValidator($identityProvider->getConfiguration(), $serviceProvider);
        $assertionValidator->addConstraintValidator(new Constraint\NotBefore());
        $assertionValidator->addConstraintValidator(new Constraint\NotOnOrAfter());
        $assertionValidator->addConstraintValidator(new SessionNotOnOrAfter());
        $assertionValidator->addConstraintValidator(new Constraint\SpIsValidAudience());

        $result = $assertionValidator->validate($assertion);
        if (!$result->isValid()) {
            throw new InvalidAssertionException(
                sprintf('Invalid Assertion in SAML Response, errors: "%s"', implode('", "', $result->getErrors()))
            );
        }

        $subject = $assertion->getSubject();
        if ($subject?->getIdentifier() instanceof EncryptedID) {
            throw new InvalidAssertionException('Encrypted NameIDs are not supported');
        }

        $confirmationValidator = new SubjectConfirmationValidator($identityProvider->getConfiguration(), $serviceProvider);
        $confirmationValidator->addConstraintValidator(new Constraint\SubjectConfirmationMethod());
        $confirmationValidator->addConstraintValidator(new Constraint\SubjectConfirmationNotBefore());
        $confirmationValidator->addConstraintValidator(new Constraint\SubjectConfirmationNotOnOrAfter());
        $confirmationValidator->addConstraintValidator(
            new Constraint\SubjectConfirmationRecipientMatches(new Destination($destination))
        );
        $confirmationValidator->addConstraintValidator(new Constraint\SubjectConfirmationResponseToMatches($response));

        foreach ($subject?->getSubjectConfirmation() ?? [] as $subjectConfirmation) {
            $result = $confirmationValidator->validate($subjectConfirmation);
            if (!$result->isValid()) {
                throw new InvalidSubjectConfirmationException(sprintf(
                    'Invalid SubjectConfirmation in Assertion, errors: "%s"',
                    implode('", "', $result->getErrors())
                ));
            }
        }
    }
}
