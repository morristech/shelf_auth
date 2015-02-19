# Authentication and Authorisation Middleware for Dart Shelf

[![Build Status](https://drone.io/bitbucket.org/andersmholmgren/shelf_auth/status.png)](https://drone.io/bitbucket.org/andersmholmgren/shelf_auth/latest)
[![Pub Version](http://img.shields.io/pub/v/shelf_auth.svg)](https://pub.dartlang.org/packages/shelf_auth)

## Introduction

Provides [Shelf](https://api.dartlang.org/apidocs/channels/be/dartdoc-viewer/shelf) middleware for authenticating users (or systems) and establishing sessions, as well as authorising access to resources.

## Usage

### Authentication
*Note: For an alternative way to build authentication middleware, see the Authentication Builder section below.*

```
var authMiddleware = authenticate([
          new BasicAuthenticator(new TestLookup()),
          new RandomAuthenticator()]));
```

Shelf Auth provides an `authenticate` function that takes a list of `Authenticator`s and an optional `SessionHandler` (see below) and creates Shelf `Middleware`.

You then add this `Middleware` at the appropriate place in your shelf pipeline

```
  var handler = const Pipeline()
      .addMiddleware(exceptionResponse())
      .addMiddleware(authMiddleware)
      .addHandler((Request request) => new Response.ok("I'm in with "
          "${getAuthenticatedContext(request).map((ac) => ac.principal.name)}\n"));

  io.serve(handler, 'localhost', 8080);

```

When the authentication middleware is invoked it goes through the authenticators in order. Each `Authenticator` does one of the following

* return a result (with a context) indicating that the authentication succeeded
* return a result indicating that the authenticator did not find any credentials relevant to it
* throw an exception indicating that the authenticator did find relevant credentials but deemed that the user should not be logged in

The first `Authenticator` that either returns a successful authentication or throws an exception wins. If an `Authenticator` indicates it did not find relevant credentials, the next authenticator in the list is called.

If no exception is thrown, then the `innerHandler` passed to the middleware will be called. If the authentication was successful then the request will contain authentication related data in the request context. This can be retrieved from the current request via the `getAuthenticatedContext` function or from the current zone via `authenticatedContext`. 

*Successful authentication results in a new zone created with the authenticated context set as a zone variable. This can be accessed with the `authenticatedContext` function.*

If none of the authenticators handle the request, then the `innerHandler` is invoked without any authentication context. Downstream handlers should treat this is access by an unauthenticated (guest) user. You can deny anonymous access by invoking the `authenticate` function with `allowAnonymousAccess: false`.

#### Establishing a Session on Login

If no `SesionHandler` is provided to the `authenticate` function then no session will be established. This means each request needs to be authenticated. This is suitable for system to system calls as well as authentication mechanisms like Basic Authentication.

To create sessions on successful login a `SessionHandler` is included

```
var authMiddleware = authenticate([new RandomAuthenticator()],
      new JwtSessionHandler('super app', 'shhh secret', testLookup));
```

The `SessionHandler` will be invoked on successful authentication if the resulting `AuthenticatedContext` supports sessions. 

*Note that in addition to indicating whether authentication succeeded, `Authenticator`s also indicate whether session creation is allowed. For some authentication mechanisms (e.g. server to server calls) it may not be desirable to create a session.*

`SessionHandler`s provide an `Authenticator` that will always be the first authenticator called for a request. The other authenticators will only be called if there is no active session.

*Note that Shelf Auth does not cover the storage (adding / retrieving) of session attributes. This is out of scope. Only the authentication related parts of session handling are in scope. Any session storage libraries that support Shelf Auth headers or can be integrated with them will work with Shelf auth.*

#### Authenticators

Shelf Auth provides the following authenticators out of the box:

##### BasicAuthenticator
Supports Basic Authentication (http://tools.ietf.org/html/rfc2617)

By default the `BasicAuthenticator` does not support session creation. This can be overriden when creating the authenticator as follows

```
new BasicAuthenticator(new TestLookup(), sessionCreationAllowed: true)
```

##### UsernamePasswordAuthenticator
An `Authenticator` that is intended for use with a dedicated login route. It defaults to assuming a form based POST with form fields called `username` and `password` such as.

```
curl -i  -H 'contentType: application/x-www-form-urlencoded' -X POST -d 'username=fred&password=blah' http://localhost:8080/login
```

This style of authentication is almost always associated with establishing a session.

```
var loginMiddleware = authenticate(
  [new UsernamePasswordAuthenticator(lookupByUsernamePassword)],
  sessionHandler: sessionHandler);
```

You can set up a login route (in this example using [shelf_route](https://pub.dartlang.org/packages/shelf_route)) and pass in this middleware.

```
rootRouter.post('/login', (Request request) => new Response.ok(
    "I'm now logged in as ${loggedInUsername(request)}\n"),
    middleware: loginMiddleware);
```

Now you typically set up other routes which are accessed via the session that was established on log in.

```
var defaultAuthMiddleware = authenticate([],
    sessionHandler: sessionHandler, allowHttp: true,
    allowAnonymousAccess: false);
      
rootRouter.child('/authenticated', middleware: defaultAuthMiddleware)
    ..get('/foo', (Request request) => new Response.ok(
        "Doing foo as ${loggedInUsername(request)}\n"));
```

In this example all routes starting with `/authenticated` will require a valid session. 

*The list of authenticators is expected to grow over time.* 

In addition you can easily create your own custom authenticators.

#### Session Handlers

Shelf Auth provides the following `SessionHandler`s out of the box:

##### JwtSessionHandler
This uses [JWT](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) to create authentication tokens which are returned in the `Authorization` header in the response. Subsequent requests must pass the token back in `Authorization` header. This is a [Bearer style token mechanism](https://auth0.com/blog/2014/01/07/angularjs-authentication-with-cookies-vs-token/). 
*Note: as with all security credentials passed in HTTP messages, if someone is able to intercept the request or response then they can steal the token and impersonate the user. Make sure you use HTTPS.*

*Features*

* Does not require anything to be stored on the server to support a session. Any server processes that have access to the secret used to create the token can validate it.
* Supports both an inactivity timeout and a total session timeout


*Other session handlers like a cookie based mechanism is likely to be added in the future*

#### Authentication Builder

To make it simpler to create authentication middleware, particularly when you use the bundled authenticators and session handlers, a builder is provided.

For example

```
 var authMiddleware = (builder()
    .basic(userNamePasswordLookup, 
      sessionCreationAllowed: true)
    .jwtSession('me', 'sshh', usernameLookup)
    ..allowHttp=true)
  .build();
```

*Note: this example is a bit convoluted as you don't typically want session creation with basic auth*

### Authorisation

```
var authorisationMiddleware = authorise([new SameOriginAuthoriser()]);
```

Shelf Auth provides an `authorise` function that takes a list of `Authoriser`s and creates Shelf `Middleware`.

Additionally `authorisationBuilder` provides a builder for creating authorisation middleware including the out of the box authorisers

```
var authorisationMiddleware = (authorisationBuilder()
    .sameOrigin()
    .principalWhitelist((Principal p) => p.name == 'fred'))
  .build();

```

If any `Authoriser` denies access then:

* if there is an authenticated user, a `ForbiddenException` is thrown
* otherwise a `UnauthorizedException` is thrown.

#### Authorisers

Shelf Auth provides the following authorisers out of the box:

##### AuthenticatedOnlyAuthoriser

Only allows access to authenticated users. If there is not current 
`AuthenticatedContext` in the request then access is denied.

##### SameOriginAuthoriser

Helps protect against XSRF attacks by denying access to requests where the referer is not from the same host as the request url.

##### PrincipalWhitelistAuthoriser

An `Authoriser` that allows access to any principal that is part of a given `PrincipalWhiteList`.

`PrincipalWhiteList` can be implemented in many ways. For example it check principal names against a static in memory list of names. 

```
final whitelist = [ 'fredlintstone@stone.age' ];
  
final whitelistAuthoriser = new PrincipalWhitelistAuthoriser(
    (Principal p) => whitelist.contains(p.name));
```

Or it might check the users group against a database for example.

