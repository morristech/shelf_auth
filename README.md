# Authentication Middleware for Dart Shelf

[![Build Status](https://drone.io/bitbucket.org/andersmholmgren/shelf_auth/status.png)](https://drone.io/bitbucket.org/andersmholmgren/shelf_auth/latest)

## Introduction

Provides [Shelf](https://api.dartlang.org/apidocs/channels/be/dartdoc-viewer/shelf) middleware for authenticating users (or systems) and establishing sessions.

## Usage

```
var authMiddleware = authenticate([
          new BasicAuthenticator(new TestLookup()),
          new RandomAuthenticator()]));
```

Shelf Auth provides an `authenticate` function that takes a list of `Authenticator`s and an optional `SessionHandler` (see below) and creates a Shelf `Middleware` function.

You then add this middleware at the appropriate place in your shelf pipeline

```
  var handler = const Pipeline()
      .addMiddleware(exceptionResponse())
      .addMiddleware(authMiddleware)
      .addHandler((Request request) => new Response.ok("I'm in with "
          "${getAuthenticationContext(request).map((ac) => ac.principal.name)}\n"));

  io.serve(handler, 'localhost', 8080);

```

When the authentication middleware is invoked it goes through the authenticators in order. Each `Authenticator` does one of the following

* return a result (with a context) indicating that the authentication succeeded
* return a result indicating that the authenticator did not find any credentials relevant to it
* throw an exception indicating that the authenticator did find relevant credentials but deemed that the user should not be logged in

The first `Authenticator` that either returns a successful authentication or throws an exception wins. If an `Authenticator` indicates it did not find relevant credentials, the next authenticator in the list is called.

If no exception is thrown then the `innerHandler` passed to the middleware will be called. If the authentication was successful then the request will contain authentication related data in the request context. This can be retrieved via the `getAuthenticationContext` function.

If none of the authenticators handle the request then the `innerHandler` is invoked without any authentication context. Downstream handlers should treat this is access by an unauthenticated (guest) user.

### Establishing a Session on Login

If no `SesionHandler` is provided to the `authenticate` function then no session will be established. This means each request needs to be authenticated. This is suitable for system to system calls as well as authentication mechanisms like Basic Authentication.

To create sessions on successful login a `SessionHandler` is included

```
var authMiddleware = authenticate([new RandomAuthenticator()],
      new JwtSessionHandler('super app', 'shhh secret', testLookup));
```

The `SessionHandler` will be invoked on successful authentication if the resulting `AuthenticationContext` supports sessions. 

*Note that in addition to indicating whether authentication succeeded, `Authenitcator`s also indicate whether session creation is allowed. For some authenitcation mechanisms (e.g. server to server calls) it may not be desirable to create a session.*

`SessionHandler`s provide an `Authenticator` that will always be the first authenticator called for a request. The other authenticators will only be called if there is no active session.

*Note that Shelf Auth does not cover the storage (adding / retrieving) of session attributes. This is out of scope. Only the authentication related parts of session handling are in scope. Any session storage libraries that support Shelf Auth headers or can be integrated with them will work with Shelf auth.*

### Authenticators

Shelf Auth provides the following authenticators out of the box:

#### BasicAuthenticator
Supports Basic Authentication (http://tools.ietf.org/html/rfc2617)

By default the `BasicAuthenticator` does not support session creation. This can be overriden when creating the authenticator as follows

```
new BasicAuthenticator(new TestLookup(), sessionCreationAllowed: true)
```

*The list of authenticators is expected to grow over time.* 

In addition you can easily create your own custom authenticators.

TODO: details about how to tweak parameters
- username lookups etc

### Session Handlers

Shelf Auth provides the following `SessionHandler`s out of the box:

#### JwtSessionHandler
This uses [JWT](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) to create authentication tokens which are returned in the `Authorization` header in the response. Subsequent requests must pass the token back in `Authorization` header. This is a [Bearer style token mechanism](https://auth0.com/blog/2014/01/07/angularjs-authentication-with-cookies-vs-token/). 
*Note: as with all secuirty credentials passed in HTTP messages, if someone is able to intercept the request or response then they can steal the token and impersonate the user. Make sure you use HTTPS.*

*Features*

* Does not require anything to be stored on the server to support a session. Any server processes that have access to the secret used to create the token can validate it.
* Supports both an inactivity timeout and a total session timeout

TODO:
- timeouts etc


*Other session handlers like a cookie based mechanism is likely to be added in the future*
