# UPGRADE FROM 7.X to 8.0

Version 8 moves the bundle from `simplesamlphp/saml2` 4.x and `robrichards/xmlseclibs` to `simplesamlphp/saml2` 7
and `simplesamlphp/xml-security` 3.1, and adds optional signing and decryption through an OpenConext Private Key
Agent. Without the `private_key_agent` configuration, the bundle keeps using local private keys.

## Requirements

- PHP 8.5 and Symfony 6.4 or 7.4.
- `simplesamlphp/saml2` `^7.0.0-rc4`, which is only available as a release candidate. Composer ignores stability
  flags of dependencies, so an application with `minimum-stability: stable` must allow it in its own `composer.json`:

  ```json
  "require": {
      "simplesamlphp/saml2": "^7.0.0-rc4",
      "surfnet/stepup-saml-bundle": "^8.0"
  }
  ```

  This release is tested with `7.0.0-rc4`; later release candidates may change APIs the bundle relies on.
- New dependencies: `simplesamlphp/xml-security`, `simplesamlphp/xml-common`, `psr/clock`, `symfony/clock`,
  `symfony/http-client` and `nyholm/psr7`. Remove `robrichards/xmlseclibs` unless you use it yourself.
- A `Psr\Clock\ClockInterface` service must exist; with `symfony/clock` installed, FrameworkBundle provides it.

## Namespaces and types

Search your application for `SAML2\`, `RobRichards\` and `DOMDocument`/`DOMElement` usages around the bundle.

| 7.x | 8.0 |
| --- | --- |
| `SAML2\Assertion` | `SimpleSAML\SAML2\XML\saml\Assertion` (immutable; no flat accessors) |
| `SAML2\Response\Processor` | `Surfnet\SamlBundle\SAML2\Response\ResponseProcessor` (service `surfnet_saml.saml2.response_processor`) |
| `SAML2\Response\Exception\*` | `SimpleSAML\SAML2\Response\Exception\*` |
| `RobRichards\XMLSecLibs\XMLSecurityKey` (verification) | `SimpleSAML\XMLSecurity\Key\PublicKey` |
| `RobRichards\XMLSecLibs\XMLSecurityKey` (signing) | `SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface` |
| `DOMDocument`, `DOMElement`, `DOMNode` in `Signable` and `Metadata` | `Dom\XMLDocument`, `Dom\Element`, `Dom\Node` |

`Entity\IdentityProvider` no longer extends saml2's `Configuration\IdentityProvider`, which is final in saml2 7, but
wraps it. Pass `$identityProvider->getConfiguration()` where saml2 requires its own class.

## Assertions

Use `Surfnet\SamlBundle\SAML2\Response\AssertionValues` for the values the 7.x assertion API returned:

| 7.x | 8.0 |
| --- | --- |
| `$assertion->getNameId()?->getValue()` | `AssertionValues::nameId($assertion)` |
| `$assertion->getIssuer()->getValue()` | `AssertionValues::issuer($assertion)` |
| `$assertion->getSubjectConfirmation()[0]->getSubjectConfirmationData()->getInResponseTo()` | `AssertionValues::inResponseTo($assertion)` |
| `$assertion->getAttributes()` | `AssertionValues::attributes($assertion)` |

`AssertionValues::attributes()` and the `SamlAttributesBadge` of `SamlAuthenticator` return
`array<string, list<string>>`, merging equally named attributes over all attribute statements. `AssertionAdapter`,
`AttributeSet::createFrom()` and `InResponseTo::assertEquals()` keep their API.

## Responses

- If you construct `PostBinding` yourself, inject `surfnet_saml.saml2.response_processor` instead of saml2's
  `Processor`. `ResponseProcessor::process()` takes the destination as a string and returns the assertion.
- Either the Response or the Assertion must be signed by the IdP (`UnsignedResponseException` otherwise).
- RSA-SHA1, RSA-PSS-SHA1, HMAC-SHA1, RSA v1.5 key transport and 3DES are rejected. To accept one of them for a
  legacy IdP, pass your own list to `BridgeContainer::setBlacklistedAlgorithms()`.
- A Response must carry exactly one assertion. Encrypted NameIDs and shared-key decryption are not supported.
- InResponseTo values must be NCNames, and the subject confirmation InResponseTo must match the Response's.
- `PostBinding` does not compare InResponseTo with the request you sent. `SamlAuthenticator` does; custom ACS code
  must do so itself. There is no assertion replay cache.

## AuthnRequests

`AuthnRequest` and `ReceivedAuthnRequest` keep their public API, but wrap the immutable saml2 7 `AuthnRequest`.

- `AuthnRequest::createNew(SAML2AuthnRequest $request, ?SignatureAlgorithmInterface $signer = null, ?string $relayState = null)`
  takes the signer and relay state, which saml2 7 messages no longer carry.
- The `verify()` methods of `SignatureVerifiable`, `ReceivedAuthnRequestQueryString` and `ReceivedAuthnRequestPost`
  take a `SimpleSAML\XMLSecurity\Key\PublicKey`.
- `ReceivedAuthnRequest::verify()` no longer changes the request; `verifiedWith()` returns the verified copy, or
  `null` when unsigned. After `ReceivedAuthnRequestPost::verify()`, call `getAuthnRequest()` again; earlier
  references remain unverified. `PostBinding::receiveSignedAuthnRequestFrom()` already returns the verified request.
- HTTP-Redirect signatures accept RSA-SHA256/384/512 unless blacklisted; `SignatureVerifier::verifySignatureAlgorithmSupported()`
  and verification apply the same rule. HTTP-POST signatures accept RSA-SHA256/384/512, trying the configured SP
  certificates in order to support rollover.
- Deprecated `AuthnRequest::createSigned()` rebuilds the signed query; migrate to
  `ReceivedAuthnRequestQueryString::parse()` and `RedirectBinding`, which preserve the signed bytes.
- Saml2 7 rejects `NameIDPolicy` with the transient format and `AllowCreate="true"`. Redirect requests are
  normalised; POST requests are rejected, because their XML signature covers the attribute.
- Generated XML declares namespaces on the elements that use them; compare it after canonicalization.

## Exceptions

| Case | 8.0 throws |
| --- | --- |
| Missing value in `AuthnRequest::getDestination()`/`getServiceProvider()`, `ReceivedAuthnRequest::getAssertionConsumerServiceURL()`, or no private key in `SigningService::sign()` | `Surfnet\SamlBundle\Exception\RuntimeException` (was `TypeError`) |
| Invalid input to `ReceivedAuthnRequest::from()`/`fromHttpRedirectBinding()` | `InvalidAuthnRequestException` (was `InvalidArgumentException`) |
| Unknown parameter in `AuthnRequestRebuilder::with()` | `InvalidArgumentException` (was ignored) |
| Malformed or invalid AuthnRequest (POST and Redirect), invalid or empty `SAMLResponse` | `BadRequestHttpException` |

`AuthnFailedSamlResponseException` and `NoAuthnContextSamlResponseException` now extend
`SimpleSAML\SAML2\Response\Exception\PreconditionNotMetException`.

## Signing and metadata

- Signed metadata gets a generated `ID` on its root element when the template has none.
- Applications with a hosted IdP should sign their responses with `Surfnet\SamlBundle\Signing\Signers::forHostedEntity()`,
  so that agent identities sign through the agent.
- Every `Signers` entry point signs with RSA-SHA256 unless you pass RSA-SHA384 or RSA-SHA512 as the optional last
  argument. Other or blacklisted algorithms throw `UnsupportedAlgorithmException` and are never replaced; check them
  in advance with `Signers::supports()`. Agent identities need the algorithm in `algorithms.signature`.

## Private Key Agent (optional)

The new `private_key_agent` section and `use_private_key_agent` flags are described in the README. Nothing changes
for applications that do not enable them.

- Certificate files are checked on first agent use, not during kernel boot or cache warmup. Run
  `bin/console surfnet:saml:validate-private-key-agent` during deployment once they are mounted.
- Agent failures throw `SimpleSAML\XMLSecurity\Exception\PrivateKeyAgentExceptionInterface` exceptions, which the
  bundle does not map. Catch them where you translate errors for users. There are no retries or circuit breaker.
- The agent algorithms are registered process-wide when the kernel boots; differently configured kernels in one
  process must not perform agent operations concurrently.

## Known limitations of saml2 7.0.0-rc4 and xml-security 3.1.0

- Attribute values with `xsi:type` `xs:nonNegativeInteger`, `xs:nonPositiveInteger`, `xs:positiveInteger` or
  `xs:normalizedString` cause a PHP `Error` in saml2 rc4, so such a Response cannot be processed.
- An encrypted assertion must carry exactly one `EncryptedKey`, inside the `KeyInfo` of its `EncryptedData`.
  Multi-recipient encryption and the `RetrievalMethod` layout, which 7.x decrypted, are rejected.
- `xmlenc11#rsa-oaep` without explicit `DigestMethod`/`MGF` parameters cannot be decrypted through the agent,
  because xml-security asks it for SHA-256 instead of the SHA-1 default. Ask IdPs to use `xmlenc#rsa-oaep-mgf1p` or
  explicit OAEP parameters. Local keys are not affected.
- Do not use saml2's `HTTPRedirect` binding or `Response\Processor` directly: they emit invalid redirect signatures
  and cannot decrypt assertions respectively.

## Security

XML signatures with XPath transforms are rejected. The `composer audit` ignores for GHSA-5cjr-mxj5-wmrx and
GHSA-6929-8p9f-26jx, which only affect saml2 4.x, are removed.

# UPGRADE FROM X to 4.1.9

When using this bundle with Symfony 4.3 you should configure the templating engine:

```yaml
framework:
    templating:
        engines:
            - twig
```        

# UPGRADE FROM 3.X to 4.X
This release makes error reporting more specific. This release changed the API of the
`ReceivedAuthnRequestQueryString::getSignatureAlgorithm` method, returning the signature algorithm url decoded. Any
code using this method should be updated removing the url_decode call to prevent double decoding of the sigalg value.

# UPGRADE FROM 2.X to 3.X

## SimpleSamlPHP SAML2
The most noticable change is the upgrade of the `simplesamlphp/saml2` library upgrade from version 1 to 3. This
resulted in a bundle wide upgrade of the SAML2 namespaces and the implementation of the SAML2 NameID implementaion.

### Update instruction
When upgrading the library some other dependencies are to be upgraded most notable is `robrichards/xmlseclibs`. To
streamline the upgrade the following installtion instructions are recommended:

```
composer remove surfnet/stepup-saml-bundle --ignore-platform-reqs
composer require surfnet/stepup-saml-bundle "^3.0" --ignore-platform-reqs
```

:grey_exclamation: Simply running `composer update surfnet/stepup-saml-bundle "^3.0"` will probably fail as other 
dependencies will block the update of the package.

### Code changes
After updating the SAML2 library, we advice you to scan your project for usages of the SAML2 library. You can do 
this by grepping your project for usages of the old PEAR style SAML2 classnames.

**Namespace**

Grep for usages `SAML2_` in your application. PEAR style class references should be updated to their PSR 
counterparts. Doing so is quite easy.

```
// old style
use SAML2_Assertion;

// new style
use SAML2\Assertion;
```

**NameID**

Using NameID values was changed in the SAML2 library. Instead of receiving an array representation of the NameId 
`['Value' => 'john_doe', 'Format' => 'unspecified')`, a value object is returned. Please inspect your project
for usages of the getNameId method on assertions.

**XMLSecurityKey**

Finally all usages of `XMLSecurityKey` should be checked. The `XMLSecurityKey` objects are now loaded from the
`RobRichards` namespace.

# UPGRADE FROM 1.X to 2.X

## Multiplicity

The multiplicity functionality has been removed from `Surfnet\SamlBundle\SAML2\Attribute\AttributeDefinition`.
 This means that the method `AttributeDefinition::getMultiplicity()` no longer exists. Furthermore, the related
 constants `AttributeDefinition::MULTIPLICITY_SINGLE` and `AttributeDefinition::MULTIPLICITY_MULTIPLE` have been
 removed. 
 
**WARNING** The value of an attribute is now always an array of strings, it can no longer be `null` or `string`.
 This means code relying on the values of attributes should be modified to always accept `string[]` as return value
 and handle accordingly.

The following deprecated methods have been removed:

| Class                                                | Removed method   | Replaced with         |
| ---------------------------------------------------- | ---------------- | --------------------- |
| `Surfnet\SamlBundle\SAML2\Response\AssertionAdapter` | `getAttribute()` | `getAttributeValue()` |
