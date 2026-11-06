# UPGRADE FROM 7.X to 8.0

Version 8 moves the bundle from `simplesamlphp/saml2` 4.x and `robrichards/xmlseclibs` to `simplesamlphp/saml2` 7
and `simplesamlphp/xml-security` 3.1, and adds optional signing and decryption through an OpenConext Private Key
Agent. Without the new `private_key_agent` configuration, the bundle keeps signing and decrypting with local private
keys.

## Requirements

- PHP 8.5 (saml2 7 requires it) and Symfony 6.4 or 7.4.
- `simplesamlphp/saml2` `^7.0.0-rc4`. At the time of this release saml2 7 is only available as a release candidate.
  Composer ignores stability flags of dependencies, so an application with `minimum-stability: stable` must allow
  it in its own `composer.json`:

  ```json
  "require": {
      "simplesamlphp/saml2": "^7.0.0-rc4",
      "surfnet/stepup-saml-bundle": "^8.0"
  }
  ```

  Later release candidates may change saml2 APIs the bundle relies on; this release is tested with `7.0.0-rc4`.
- New direct dependencies: `simplesamlphp/xml-security` `^3.1`, `simplesamlphp/xml-common` `^3.0`, `psr/clock`,
  `symfony/clock`, `symfony/http-client` and `nyholm/psr7`. `robrichards/xmlseclibs` is no longer required; remove it
  from your application unless you use it yourself.
- The bundle registers a `Psr\Clock\ClockInterface` argument for its saml2 container. The service must exist; with
  `symfony/clock` installed, FrameworkBundle provides it.

## Namespaces and types

All saml2 classes moved from `SAML2\` to `SimpleSAML\SAML2\`, and most XML classes changed. Search your
application for `SAML2\`, `RobRichards\` and `DOMDocument`/`DOMElement` usages around the bundle.

| 7.x | 8.0 |
| --- | --- |
| `SAML2\Assertion` | `SimpleSAML\SAML2\XML\saml\Assertion` (immutable; no flat accessors) |
| `SAML2\Response\Processor` | `Surfnet\SamlBundle\SAML2\Response\ResponseProcessor` (service `surfnet_saml.saml2.response_processor`) |
| `SAML2\Response\Exception\*` | `SimpleSAML\SAML2\Response\Exception\*` |
| `RobRichards\XMLSecLibs\XMLSecurityKey` (verification) | `SimpleSAML\XMLSecurity\Key\PublicKey` |
| `RobRichards\XMLSecLibs\XMLSecurityKey` (signing) | `SimpleSAML\XMLSecurity\Alg\Signature\SignatureAlgorithmInterface` |
| `DOMDocument`, `DOMElement`, `DOMNode` in `Signable` and `Metadata` | `Dom\XMLDocument`, `Dom\Element`, `Dom\Node` |

`Surfnet\SamlBundle\Entity\IdentityProvider` no longer extends saml2's `Configuration\IdentityProvider`, which is
final in saml2 7. It wraps it and implements `CertificateProvider`, `DecryptionProvider`, `EntityIdProvider` and
`Queryable`. Pass `$identityProvider->getConfiguration()` to saml2 APIs and `instanceof` checks that require
`SimpleSAML\SAML2\Configuration\IdentityProvider`. `Entity\ServiceProvider` still extends saml2's
`Configuration\ServiceProvider`.

## Assertions

The saml2 7 assertion no longer offers `getNameId()`, `getAttributes()`, `getSubjectConfirmation()` or a string
issuer. Use `Surfnet\SamlBundle\SAML2\Response\AssertionValues` for the values the 7.x API returned:

| 7.x | 8.0 |
| --- | --- |
| `$assertion->getNameId()?->getValue()` | `AssertionValues::nameId($assertion)` |
| `$assertion->getIssuer()->getValue()` | `AssertionValues::issuer($assertion)` |
| `$assertion->getSubjectConfirmation()[0]->getSubjectConfirmationData()->getInResponseTo()` | `AssertionValues::inResponseTo($assertion)` |
| `$assertion->getAttributes()` | `AssertionValues::attributes($assertion)` |

`AssertionValues::attributes()` returns `array<string, list<string>>` and merges equally named attributes over all
attribute statements. Text attribute values, NameID and Issuer retain the previous trimming behavior; serialized XML
attribute values are preserved. This does not relax parsing: saml2 rejects whitespace around a default entity-format
Issuer as an invalid URI before these accessors run. The `SamlAttributesBadge` of `SamlAuthenticator` carries the same structure.
`AssertionAdapter`, `AttributeSet::createFrom()` and `InResponseTo::assertEquals()` keep their API.

## Responses

`PostBinding::processResponse()` still returns a single assertion, but processing changed:

- The `PostBinding` constructor takes the bundle's `ResponseProcessor` instead of saml2's `Processor`. If you
  construct `PostBinding` yourself, inject `surfnet_saml.saml2.response_processor`.
- `ResponseProcessor::process()` takes the destination as a string and returns the assertion instead of a
  collection.
- The order is: status and destination, Response signature, decryption, Assertion signature, assertion and subject
  confirmation validation. Either the Response or the Assertion must be signed by the remote IdP
  (`UnsignedResponseException` otherwise). Decryption never makes an assertion trusted.
- Signatures are verified and assertions decrypted with the algorithm blacklist of the bundle's saml2 container:
  RSA-SHA1, RSA-PSS-SHA1, HMAC-SHA1, RSA v1.5 key transport and 3DES (`tripledes-cbc`) content encryption are
  rejected. To accept one of them, for example for a legacy IdP, pass your own list to
  `BridgeContainer::setBlacklistedAlgorithms()`.
- A Response must carry exactly one assertion. An encrypted assertion must carry exactly one `EncryptedKey`.
  Encrypted NameIDs and shared-key (symmetric) decryption are not supported.
- When both are present, the subject confirmation InResponseTo must match the Response's InResponseTo. As before,
  `PostBinding` does not compare it with the request your application sent: `SamlAuthenticator` does, custom ACS
  code still has to. The processor retains the legacy acceptance of missing SubjectConfirmations or missing
  Recipient, InResponseTo and NotOnOrAfter fields; the configured validators check those fields when present.
  Custom ACS code must require the confirmation fields its SSO profile needs, correlate the assertion with a
  pending request, and consume that request before establishing a session.
- `SamlAuthenticator` rejects a missing or mismatched confirmation InResponseTo against its pending request ID and
  clears that ID on authentication success. There is no separate assertion replay cache; cross-session replay
  protection and unsolicited SSO policy remain application responsibilities.
- InResponseTo values must be NCNames, as saml2 7 requires.
- An invalid or empty base64 `SAMLResponse` produces a `BadRequestHttpException`.
- Non-success statuses keep their mapping to `AuthnFailedSamlResponseException` and
  `NoAuthnContextSamlResponseException`, which now extend `SimpleSAML\SAML2\Response\Exception\PreconditionNotMetException`.

## AuthnRequests

`AuthnRequest` and `ReceivedAuthnRequest` keep their public API, but wrap the immutable saml2 7 `AuthnRequest`.

- `AuthnRequest::createNew()` takes the signer and the relay state as optional arguments:
  `createNew(SAML2AuthnRequest $request, ?SignatureAlgorithmInterface $signer = null, ?string $relayState = null)`.
  Saml2 7 messages no longer carry a relay state or signing key.
- `AuthnRequest::getDestination()`, `AuthnRequest::getServiceProvider()` and
  `ReceivedAuthnRequest::getAssertionConsumerServiceURL()` throw `Surfnet\SamlBundle\Exception\RuntimeException`
  instead of a `TypeError` when the value is missing.
- Deprecated `AuthnRequest::createSigned()` rejects empty or malformed base64 signatures with `InvalidRequestException`.
  Its verifier accepts RSA-SHA256 only. It still rebuilds the signed query because its API does not receive the
  original encoded query; migrate incoming Redirect requests to `ReceivedAuthnRequestQueryString::parse()` and
  `RedirectBinding`, which preserve the signed bytes. Empty and `"0"` RelayState values are retained.
- `SignatureVerifiable::verify()`, `ReceivedAuthnRequestQueryString::verify()` and `ReceivedAuthnRequestPost::verify()`
  take a `SimpleSAML\XMLSecurity\Key\PublicKey`.
- POST AuthnRequest verification tries the configured SP certificates in order, continuing after a signature
  mismatch so that rollover certificates work. A forbidden transform or unsupported algorithm still rejects the request.
- `PostBinding::receiveSignedAuthnRequestFrom()` returns the request as covered by the XML signature, and rejects it
  when its Destination or Issuer differ from the values checked before verification. Extensions are also reloaded
  from that verified request.
- `setSubject()` preserves SubjectConfirmations and `setScoping()` preserves the IDPList.
- `ReceivedAuthnRequest::from()` and `ReceivedAuthnRequest::fromHttpRedirectBinding()` throw
  `Surfnet\SamlBundle\Exception\InvalidAuthnRequestException` (a `RuntimeException`) for empty input, malformed XML,
  schema violations and non-AuthnRequest messages, instead of `InvalidArgumentException`. SAML protocol violations
  still throw saml2's `ProtocolViolationException`.
- Malformed XML, schema violations and unexpected message types produce `BadRequestHttpException` (HTTP 400)
  for both POST and Redirect AuthnRequests. Protocol violations also produce HTTP 400 in both bindings.
- XML signature verification accepts RSA signature methods only; unsupported methods such as HMAC are rejected
  without a key-type error.
- Saml2 7 rejects `NameIDPolicy` with the transient format and `AllowCreate="true"` (SAML errata E14). Requests
  received through HTTP-Redirect are normalised before parsing, because their signature covers the query string.
  Requests received through HTTP-POST are not, because the XML signature covers the attribute; these and other
  saml2 protocol violations now produce a `BadRequestHttpException` (HTTP 400).
- Generated XML declares namespaces on the elements that use them. The XML is semantically equal; compare it after
  canonicalization rather than as a string.

## Signing and metadata

- `Signable::getRootDomElement()` returns a `Dom\Element`, `Signable::getAppendBeforeNode()` a `?Dom\Node`, and
  `Metadata::$document` is a `?Dom\XMLDocument`.
- Signed metadata gets a generated `ID` on its root element when the template has none, so that the signature
  reference has a URI.
- `SigningService::sign()` throws `Surfnet\SamlBundle\Exception\RuntimeException` instead of a `TypeError` when no
  private key file is configured.
- New `Surfnet\SamlBundle\Signing\Signers` returns the RSA-SHA256 signer of a hosted entity (`forHostedEntity()`).
  Applications with a hosted IdP should use it to sign their responses, so that agent identities sign through the
  agent.

## Private Key Agent (optional)

The new `surfnet_saml.private_key_agent` section and the `use_private_key_agent` flags of
`hosted.service_provider`, `hosted.identity_provider` and `hosted.metadata` let an OpenConext Private Key Agent
perform the RSA private-key operations. See the README for the configuration. Nothing changes for applications that
do not enable it.

- An identity with `use_private_key_agent: true` must not configure `private_key`, and its `public_key` must point
  at the certificate of an agent key with the `sign` operation. The bundle checks this when the container is
  compiled and when the kernel boots, so the certificate files must be readable at boot.
- A hosted service provider with `use_private_key_agent: true` that receives encrypted assertions needs at least one
  agent key with the `decrypt` operation. This is not checked at boot: without one, encrypted assertions are
  rejected at runtime with `InvalidAssertionException`.
- `private_key_agent.algorithms.signature` must include RSA-SHA256 when a hosted identity signs through the agent;
  the container rejects configurations that omit it.
- `private_key_agent.enabled` accepts `%env(PKA_ENABLED)%` without a cast. The value is resolved at container
  compilation and converted with PHP's boolean validation (`true`/`false`, `1`/`0`, `on`/`off`, `yes`/`no`);
  invalid values fail compilation. Symfony rejects cast expressions such as `%env(bool:PKA_ENABLED)%` when
  resolved inside an extension. Rebuild the container cache after changing the variable. Tokens and the agent URL
  remain lazy. Hosted `use_private_key_agent` flags still require literal booleans.
- Local-key operations do not initialize the agent backend or resolve its tokens and URL.
- Agent key-name validation reports only invalid names, without token values. Unregistered or unsupported agent
  key-transport algorithms produce `InvalidAssertionException` instead of a key-type error.
- The bundle never falls back to a local private key. Agent failures surface as
  `SimpleSAML\XMLSecurity\Exception\PrivateKeyAgentExceptionInterface` exceptions (for example
  `AgentUnavailableException`, `AuthenticationException`, `AuthorizationException`); the bundle does not map them to
  its own exceptions. Catch them where you translate errors for users.
- Each signature or decryption costs one agent request, bounded by `timeout` and `max_duration`, with no retries and
  no circuit breaker. Add a circuit breaker in your application or infrastructure if you need one.
- The agent algorithms are registered with xml-security's process-wide algorithm factories when the kernel boots.
  In worker SAPIs (FrankenPHP, RoadRunner, Swoole) the registration therefore lives as long as the worker.
- `KeyPair::$usePrivateKeyAgent` and `MetadataConfiguration::$usePrivateKeyAgent` select agent signing for metadata.
  `ResponseProcessor` takes an optional `KeyMap` as fourth constructor argument. `Entity\ServiceProvider` and
  `Entity\IdentityProvider` expose `usesPrivateKeyAgent()`.
- `AuthnRequestFactory::createNewRequest()` signs through the agent for an agent SP. Its error for a missing local
  key now names the entity.

## Known limitations of saml2 7.0.0-rc4 and xml-security 3.1.0

- Attribute values with `xsi:type` `xs:nonNegativeInteger`, `xs:nonPositiveInteger`, `xs:positiveInteger` or
  `xs:normalizedString` fail with a PHP `Error` (class not found) in saml2 rc4, so a Response carrying them cannot
  be processed. Fixed in saml2 after rc4, not yet released.
- An encrypted assertion is decrypted with the first `EncryptedKey` of its `KeyInfo` only; the bundle rejects
  assertions with more than one `EncryptedKey`, so multi-recipient encryption is not supported. An `EncryptedKey`
  placed next to the `EncryptedData` instead of inside its `KeyInfo` (the `RetrievalMethod` layout) is rejected
  with `InvalidAssertionException`; 7.x decrypted it.
- `xmlenc11#rsa-oaep` without explicit `DigestMethod`/`MGF` parameters cannot be decrypted through the Private Key
  Agent (see the README). Local keys are not affected.
- The `HTTPRedirect` binding and the `Response\Processor` of saml2 rc4 are not used by the bundle, because they emit
  invalid redirect signatures and cannot decrypt assertions respectively. Do not use them directly.

## Removed audit ignores

The `composer audit` ignores for GHSA-5cjr-mxj5-wmrx and GHSA-6929-8p9f-26jx are removed; both advisories only
affect saml2 4.x. `SignatureTransformGuard` rejects XPath transforms before XML-signature verification in
`ReceivedAuthnRequest::verify()` and `ResponseProcessor` (Response and Assertion signatures, including decrypted
Assertions). `PostBinding::processResponse()` also scans the incoming document before parsing. These checks cover
POST AuthnRequests and direct processor callers, because xml-security 3 evaluates XPath transforms and SAML never
needs them. Redirect signatures cover query-string bytes rather than XML transforms.

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
