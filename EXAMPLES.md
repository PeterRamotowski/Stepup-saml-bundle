Here are two example controllers here in the hope it might still be useful for the reader.

I'm assuming your application is the service provider, and you want to
authenticate users with a remote identity provider. This means you need two
endpoints:

 - an endpoint to start authentication, I call this the acs init endpoint
 - an endpoint to process a SAML response, I call this the acs respond endpoint

Your init endpoint might look something like this:

```php
<?php

namespace YourApp\Controller\Saml;

use YourApp\Saml\AcsContextInterface;
use Psr\Log\LoggerInterface;
use Surfnet\SamlBundle\Entity\HostedEntities;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\SAML2\AuthnRequestFactory;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class AcsInitController
{
    #[Route('/saml/acs/init', name: 'saml_acs_init', methods: ['GET'])]
    public function __invoke(
        Request $httpRequest,
        HostedEntities $hostedEntities,
        IdentityProvider $idp,
        AcsContextInterface $context,
        LoggerInterface $logger
    ): Response {
        $request = AuthnRequestFactory::createNewRequest(
            $hostedEntities->getServiceProvider(),
            $idp
        );

        $logger->info(
            sprintf(
                'Starting SSO request with ID %s to IDP %s',
                $request->getRequestId(),
                $idp->getEntityId()
            )
        );

        // Store the request so we can validate the response on acs respond.
        $context->setAuthnRequest($request);

        // That's it, we're good to go!
        return new RedirectResponse(
            sprintf(
                '%s?%s',
                $idp->getSsoUrl(),
                $request->buildRequestQuery()
            )
        );
    }
}
```

The `$idp` argument should be wired to the
`surfnet_saml.remote.idp` service. The `$context` argument is an
object from your own application where you store some state in the session,
like the request or request ID that was sent.

The second endpoint is the actual ACS endpoint that receives and validates the
SAML response and redirects to your application:

```php
namespace YourApp\Controller\Saml;

use Exception;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\SAML2\Response\AssertionValues;
use YourApp\Saml\AcsContextInterface;
use Psr\Log\LoggerInterface;
use Surfnet\SamlBundle\Entity\HostedEntities;
use Surfnet\SamlBundle\Http\PostBinding;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Routing\Attribute\Route;

class AcsRespondController
{
    #[Route('/saml/acs', name: 'saml_acs_respond', methods: ['POST'])]
    public function __invoke(
        HostedEntities $hostedEntities,
        AcsContextInterface $context,
        IdentityProvider $idp,
        PostBinding $binding,
        Request $httpRequest,
        LoggerInterface $logger
    ): RedirectResponse {
        $response = $httpRequest->request->get('SAMLResponse');

        if (!$response) {
            throw new BadRequestHttpException(
                'No SAMLResponse parameter found in request to ACS respond endpoint'
            );
        }

        if (!$context->hasAuthnRequest()) {
            $logger->error('Received assertion but no authn request found in context: session lost?');

            throw new BadRequestHttpException('Received an assertion but SSO was not initiated here');
        }

        try {
            $assertion = $binding->processResponse(
                $httpRequest,
                $idp,
                $hostedEntities->getServiceProvider()
            );
        } catch (Exception $e) {
            $logger->error(
                'Error processing ACS request',
                ['exception_class' => $e::class]
            );

            throw new BadRequestHttpException('Error processing ACS request');
        }

        $inResponseTo = AssertionValues::inResponseTo($assertion);
        $requestId = $context->getAuthnRequest()->getRequestId();
        if ($inResponseTo !== $requestId) {
            throw new BadRequestHttpException(
                "InResponseTo of assertion {$inResponseTo} does not match request ID {$requestId}"
            );
        }

        // You should clear the authn request from your session state, and set the user as logged
        // in based on the attributes found
        $context->clearAuthnRequest();

        return new RedirectResponse(
            '/redirect-to-somewhere'
        );
    }
}
```

Avoid logging raw SAML messages or user attributes in application logs. The SAML
bundle checks that the assertion answers the Response's InResponseTo, but not
that it answers the request your application sent, so that check is included
in this example.

`PostBinding::processResponse()` accepts a Response only when the Response or
the Assertion is signed by the IdP, and returns the single assertion it carries,
decrypted when it was encrypted. When the hosted SP uses the Private Key Agent
(see the README), decryption and the AuthnRequest signature go through the agent
and agent failures surface as
`SimpleSAML\XMLSecurity\Exception\PrivateKeyAgentExceptionInterface`
exceptions; the generic `catch (Exception $e)` above handles them too.

## SAML Authentications
As of version 5 of this bundle, a Symfony Security Authentication SamlAuthenticator was added to the project. 
The simplified Authentication mechanism added in Symfony 5 made it much easier to facilitate this feature via the 
Stepup Saml Bundle. Allowing SP's to also perform SAML 2.0 HTTP authentications. 

Only HTTP Redirect binding is implemented for authentication. The SAML response assertion consumption service (ACS) is 
performed using HTTP POST binding.

To get this feature to work you will need to perform the following steps

1. Enable the `enable_authentication` in the `surfnet_saml` configuration. By default this is disabled.
2. Configure your project as an SP and set up at least one remote IdP. See steps above on some help with setting this up, or consult the README.md
3. Create a `Security\Authentication\Provider\SamlProvider` And have it implement the `Surfnet\SamlBundle\Security\Authentication\Provider\SamlProviderInterface` and the `UserProviderInterface`
4. In `config/packages/security.yaml`: setup a `saml_based` firewall and create a `providers` entry. See code example 1 below.
5. Add the `SamlProvider` service to your services.yaml. See example below in block 2.
6. Configure the ACS route name of SP in your `.env` file. Example:  `acs_location_route_name='assertion_consumer_service'`. Your Saml Controller ACS location action should use the same route name. 
7. Optionally create a `Security\Authentication\Handler\FailureHandler`. Here you can define what behavior is required when authentication failed. For example you can do a redirect to a certain page. Or show an error page. Must implement the `AuthenticationFailureHandlerInterface`. See code example 3 for details. A very simple implementation is provided in the bundle. Showing a very simple unstyled authn failed error page.
 
### Code example 1: setting up security.yaml

```yaml
security:
  # Other security entries are not shown in this code example. Only the required entries for getting SAML 
  # authentications with the stepup-saml-bundle are stated below

  access_control:
    - { path: ^/saml, roles: PUBLIC_ACCESS, requires_channel: https }
    - { path: ^/, roles: IS_AUTHENTICATED_FULLY, requires_channel: https }
  
  providers:
    saml-provider:
      id: YourApp\Security\Authentication\Provider\SamlProvider
      
  firewalls:
    login_firewall:
      pattern:    ^/saml/metadata
    
    saml_based:
      custom_authenticators:
        - Surfnet\SamlBundle\Security\Authentication\SamlAuthenticator
```

### Code example 2: services.yaml
```yaml

    # This is just an example of the dependencies a SamlProvider could have, tailor this provider to your own needs
    surfnet_saml.saml_provider:
        class: YourApp\Security\Authentication\Provider\SamlProvider
        arguments:
            - '@YourApp\Repository\UserRepository'
            - '@surfnet_saml.saml.attribute_dictionary'
            - '@logger'

    # Make the provider available for autowiring by its application class.
    YourApp\Security\Authentication\Provider\SamlProvider:
        alias: surfnet_saml.saml_provider

```

### Code example 3: example failure handler
```php
<?php

namespace YourApp\Security\Authentication\Handler;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationFailureHandler;
use Symfony\Component\Security\Http\HttpUtils;
use Twig\Environment;

class FailureHandler extends DefaultAuthenticationFailureHandler
{
    public function __construct(
        HttpKernelInterface $httpKernel,
        HttpUtils $httpUtils,
        array $options = [],
        LoggerInterface $logger = null,
        private Environment $templating,
    ) {
        parent::__construct($httpKernel, $httpUtils, $options, $logger);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $this->logger->notice(
            sprintf(
                'Authentication failure %s: %s',
                $exception->getMessageKey(),
                $exception->getMessage()
            )
        );

        $responseBody = $this->templating->render(
            '@YourApp/Exception/authnFailed.html.twig',
            ['exception' => $exception]
        );

        return new Response($responseBody, Response::HTTP_UNAUTHORIZED);
    }
}
```
