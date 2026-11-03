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

use SimpleSAML\SAML2\Certificate\KeyCollection;
use SimpleSAML\SAML2\Certificate\KeyLoader;
use SimpleSAML\SAML2\Certificate\X509;
use SimpleSAML\SAML2\Configuration\CertificateProvider;
use SimpleSAML\SAML2\Utilities\File;
use SimpleSAML\XMLSchema\Type\Base64BinaryValue;
use SimpleSAML\XMLSecurity\CryptoEncoding\PEM;
use SimpleSAML\XMLSecurity\Key\PublicKey;
use SimpleSAML\XMLSecurity\Key\X509Certificate;
use SimpleSAML\XMLSecurity\Utils\Certificate;
use SimpleSAML\XMLSecurity\XML\ds\KeyInfo;
use SimpleSAML\XMLSecurity\XML\ds\X509Certificate as X509CertificateElement;
use SimpleSAML\XMLSecurity\XML\ds\X509Data;
use Surfnet\SamlBundle\Exception\RuntimeException;

/**
 * Conversions between saml2's certificate key objects and xml-security keys.
 *
 * saml2 7.0.0-rc4 KeyLoader::loadCertificateFile() checks certificate files against the PUBLIC KEY pattern and
 * therefore rejects every PEM certificate; extract() loads certificate files itself and delegates everything else.
 *
 * @internal
 * @SuppressWarnings("PHPMD.CouplingBetweenObjects")
 */
final class CertificateKeys
{
    public static function extract(KeyLoader $keyLoader, CertificateProvider $provider): KeyCollection
    {
        $certificateFile = $provider->getCertificateFile();
        if ($provider->getKeys() !== null || $provider->getCertificateData() !== null || $certificateFile === null) {
            return $keyLoader::extractPublicKeys($provider);
        }

        $keys = new KeyCollection();
        $keys->add(X509::createFromCertificateData(self::certificateDataFromFile($certificateFile)));

        return $keys;
    }

    public static function certificateDataFromFile(string $certificateFile): string
    {
        $certificate = File::getFileContents($certificateFile);
        if (!Certificate::hasValidStructure($certificate, Certificate::CERTIFICATE_PATTERN)) {
            throw new RuntimeException(sprintf('Could not find a PEM encoded certificate in "%s"', $certificateFile));
        }

        return Certificate::stripHeaders($certificate, Certificate::CERTIFICATE_PATTERN);
    }

    public static function toPublicKey(X509 $certificate): PublicKey
    {
        return (new X509Certificate(PEM::fromString($certificate->getCertificate())))->getPublicKey();
    }

    public static function toKeyInfo(X509 $certificate): KeyInfo
    {
        $certificateData = $certificate['X509Certificate'];
        if (!is_string($certificateData) || $certificateData === '') {
            throw new RuntimeException('The certificate has no X509Certificate data');
        }

        return new KeyInfo([
            new X509Data([new X509CertificateElement(Base64BinaryValue::fromString($certificateData))]),
        ]);
    }
}
