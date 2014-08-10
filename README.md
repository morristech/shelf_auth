# Authentication Middleware for Dart Shelf

[![Build Status](https://drone.io/bitbucket.org/andersmholmgren/shelf_auth/status.png)](https://drone.io/bitbucket.org/andersmholmgren/shelf_auth/latest)

## Introduction

Provides [Shelf](https://api.dartlang.org/apidocs/channels/be/dartdoc-viewer/shelf) middleware for authenticating users (or systems) and establishing sessions.

## Usage

```
  var handler = const Pipeline()
      .addMiddleware(exceptionResponse())
      .addMiddleware(authenticate([
          new BasicAuthenticator(new TestLookup()),
          new RandomAuthenticator()]))
      .addHandler((Request request) => new Response.ok("I'm in with "
          "${getAuthenticationContext(request).map((ac) => ac.principal.name)}\n"));

  io.serve(handler, 'localhost', 8080);

```

Shelf Auth provides a function `authenticate` that takes a list of `Authenticator`s where the first to either succeed or throw wins.

Supports custom Authenticators in addition to some standard out of the box implementations.

The `SessionHandler` if provided will be invoked on successful authentication if the resulting `AuthenticationContext` supports sessions.

### Authenticators

Shelf Auth provides the following authenticators out of the box:

* `BasicAuthenticator`. Supports Basic Authentication (http://tools.ietf.org/html/rfc2617)

*Note: work in progress. Too immature just yet to use. Check back soon* 