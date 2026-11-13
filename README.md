# SURFnet SamlBundle

<!--
       [![Build Status](https://travis-ci.org/SURFnet/Stepup-bundle.svg)](https://travis-ci.org/SURFnet/Stepup-bundle) [![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/SURFnet/Stepup-bundle/badges/quality-score.png?b=develop)](https://scrutinizer-ci.com/g/SURFnet/Stepup-bundle/?branch=develop) [![SensioLabs Insight](https://insight.sensiolabs.com/projects/5b8b8d8b-e917-4954-818b-782d9e181c75/mini.png)](https://insight.sensiolabs.com/projects/5b8b8d8b-e917-4954-818b-782d9e181c75)
-->

A PHP Symfony bundle that adds SAML capabilities to your application using [simplesamlphp/saml2][1]

Developed as part of the [OpenConext-Stepup Gateway][2] and related OpenConext-Stepup applications that use SAML 2.0

## Installation

* Add the package to your Composer file
  ```sh
  composer require surfnet/stepup-saml-bundle
  ```

How to install with Symfony 6.4 or 7.4
 
1. Require the bundle. Version 8 requires PHP 8.5 and the saml2 7 release candidate, see [UPGRADING.md](UPGRADING.md):
   ```sh
   composer require simplesamlphp/saml2:^7.0.0-rc4 surfnet/stepup-saml-bundle:^8.0
   ```
2. Enable the bundle in `config/bundles.php` add to the return statement: `Surfnet\SamlBundle\SurfnetSamlBundle::class => ['all' => true],`
3. Specify the bundle configuration in `config/packages/surfnet_saml.yaml`, consult the configuration section below for available options.
4. Configure the templates to the Twig Bundle by adding `'%kernel.project_dir%/vendor/surfnet/stepup-saml-bundle/templates': 'SurfnetSaml'` to your twig.yaml config file(s) 

## Configuration

```yaml
surfnet_saml:
    enable_authentication: false
    hosted:
        attribute_dictionary:
            ignore_unknown_attributes: false
        service_provider:
            enabled: true
            assertion_consumer_route: name_of_the_route_of_the_assertion_consumer_url
            public_key: %surfnet_saml_sp_publickey%
            private_key: %surfnet_saml_sp_privatekey%
        identity_provider:
            enabled: true
            service_provider_repository: service.name.of.entity_repository
            sso_route: name_of_the_route_of_the_single_sign_on_url
            public_key: %surfnet_saml_idp_publickey%
            private_key: %surfnet_saml_idp_privatekey%
        metadata:
            entity_id_route: name_of_the_route_of_metadata_url
            public_key: %surfnet_saml_metadata_publickey%
            private_key: %surfnet_saml_metadata_privatekey%
    remote:
        identity_provider:
            enabled: true
            entity_id: %surfnet_saml_remote_idp_entity_id%
            sso_url: %surfnet_saml_remote_idp_sso_url%
            certificate: %surfnet_saml_remote_idp_certificate%
        service_providers:
            - entity_id: "%surfnet_saml_remote_sp_entity_id%"
              certificate_file: "%surfnet_saml_remote_sp_certificate%"
              assertion_consumer_service_url: "%surfnet_saml_remote_sp_acs%"            
```

The `hosted:` configuration lists the configuration for the services (SP, IdP or both) that your application offers. SP and IdP
 functionality can be turned off and on individually through the repective `enabled` flags.

The `remote:` configuration lists, if enabled, the configuration for one or more remote service providers and identity providers to connect to.
If your application authenticates with a single identity provider, you can use the `identity_provider:` option as shown above. The identity
provider can be accessed runtime using the `@surfnet_saml.remote.idp` service.

If your application authenticates with more than one identity providers, you can omit the `identity_provider:` key from configuration and list all
identity providers under `identity_providers:`. The identity providers can be accessed by using the `@surfnet_saml.remote.identity_providers` service.
```yaml
    remote:
        identity_providers:
            -  enabled: true
               entity_id: %surfnet_saml_remote_idp_entity_id%
               sso_url: %surfnet_saml_remote_idp_sso_url%
               certificate: %surfnet_saml_remote_idp_certificate%

```

The inlined certificate in the last line can be replaced with `certificate_file` containing a filesystem path to
a file which contains said certificate.
It is recommended to use parameters as listed above. The various `publickey` and `privatekey` variables are the
 contents of the key in a single line, without the certificate etc. delimiters. The use of parameters as listed above
 is highly recommended so that the actual key contents can be kept out of the configuration files (using for instance
 a local `parameters.yml` file).

The `service_provider_repository` is a repository of service providers for which you offer IdP services. The service
configured _must_ implement the `Surfnet\SamlBundle\Entity\ServiceProviderRepository` interface.

Service providers can be provided statically by using the remote.service_providers configuration option. To use these configured service 
providers keep in mind that you need to assign `surfnet_saml.remote.service_providers` as `service_provider_repository`.

### Private Key Agent

Hosted identities can let an [OpenConext Private Key Agent][3] perform their RSA private-key operations, so that the
application never holds those private keys. The agent signs AuthnRequests and metadata, and decrypts the key of
encrypted assertions; everything else stays local. Without it the bundle uses the local `private_key` files.

```yaml
surfnet_saml:
    hosted:
        service_provider:
            enabled: true
            assertion_consumer_route: name_of_the_route_of_the_assertion_consumer_url
            public_key: '%kernel.project_dir%/config/saml/sp.crt'  # certificate of an agent key with `sign`
            use_private_key_agent: true                            # private_key must not be set
        metadata:
            entity_id_route: name_of_the_route_of_metadata_url
            public_key: '%kernel.project_dir%/config/saml/sp.crt'
            use_private_key_agent: true
    private_key_agent:
        enabled: true
        base_url: '%env(PKA_AGENT_URL)%'       # https://; http:// only for loopback with allow_insecure_http
        allow_insecure_http: false
        timeout: 3.0                           # idle timeout in seconds, 0.1-30
        max_duration: 5.0                      # total time per request in seconds, 0.1-60
        keys:
            sp-key:                            # key name in the agent, [a-zA-Z0-9_-]{1,64}
                certificate_file: '%kernel.project_dir%/config/saml/sp.crt'
                token: '%env(trim:file:PKA_TOKEN_FILE)%'
                operations: [sign, decrypt]
        algorithms:                            # defaults; weaker algorithms are rejected
            signature:
                - 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
                - 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
                - 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
            key_transport:
                - 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
                - 'http://www.w3.org/2009/xmlenc11#rsa-oaep'
```

- `use_private_key_agent` (a literal boolean) exists for `service_provider`, `identity_provider` and `metadata`.
  Keys are matched by certificate fingerprint and only used for the operations they list.
- `enabled` may use `%env(PKA_ENABLED)%` without a `bool:` cast; rebuild the container cache after changing it.
- `algorithms.signature` must include RSA-SHA256 when a hosted identity signs through the agent, and every other
  algorithm passed to `Signing\Signers` for an agent identity.
- Keep tokens out of configuration files, for example with the `file:` environment variable processor as above.
- Certificate files are loaded on first agent use, so they need not be mounted during cache warmup. Once mounted,
  run `bin/console surfnet:saml:validate-private-key-agent` during deployment; it does not contact the agent.
- Each signature or decryption is one agent request, without retries. An agent failure fails the operation and never
  falls back to a local key.
- A service provider that receives encrypted assertions needs at least one key with `decrypt`. These keys are tried
  in configuration order, or only the one the IdP names in the `EncryptedKey`.
- Rolling over the SP key: add the new key (with `sign` and `decrypt`) before the old one and point
  `service_provider.public_key` at its certificate. Remove the old key when all IdPs use the new metadata.

## Example Usage

### Symfony Authentication
As of version 5 of this bundle, we started supporting SAML authentications via the Stepup SAML bundle. This ties into 
the Symfony Security component. 

Details about how to install this into your SP, see the [EXAMPLES.md](EXAMPLES.md).

#### Overriding the ACS processor
Your application will start to try and handle all SAML Responses that are posted to your apps ACS location.
In most situations that's exactly what you want. However if you want to handle the response yourself. You can!

1. Ensure you add a RelayState statement to the AuthnRequest
2. Configure that RelayState value in the `rejected_relay_states` parameter (in your app). This value defaults to `[]`. So be sure to pass an array of string values
3. Thats it.

### Metadata Publishing

```php
<?php

namespace Acme\SamlBundle

use Surfnet\SamlBundle\Http\XMLResponse;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

class MetadataController extends Controller
{
    public function metadataAction(Request $request)
    {
        /** @var \Surfnet\SamlBundle\Metadata\MetadataFactory $metadataFactory */
        $metadataFactory = $this->get('surfnet_saml.metadata_factory');

        return new XMLResponse($metadataFactory->generate());
    }
}
```

See more examples in [EXAMPLES.md](EXAMPLES.md).


## Release strategy

### CHANGELOG.md
Please read: https://github.com/OpenConext/Stepup-Deploy/wiki/Release-Management for more information on the release strategy used in Stepup projects.

### UPGRADING.md
When introducing backwards compatible breaking changes in the bundle. Please update the UPGRADING.md file to instruct
users how to deal with these changes. This makes upgrading as painless as possible. 

[1]: https://github.com/simplesamlphp/saml2
[2]: https://github.com/OpenConext/Stepup-Gateway
[3]: https://github.com/OpenConext/OpenConext-private-key-agent
