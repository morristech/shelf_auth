// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.builder;

import 'package:shelf/shelf.dart';
import 'package:logging/logging.dart';
import 'authentication.dart';
import 'core.dart';
import 'authenticators/basic_auth.dart';
import 'principal/user_lookup.dart';
import 'session/jwt/jwt_session_handler.dart';

export 'core.dart';

final Logger _log = new Logger('shelf_auth.builder');

/// Creates a builder to help with the creation of shelf_auth middleware.
///
/// For example
///
/// ```
/// var authMiddleware = (builder()
///    .basic(userNamePasswordLookup, sessionCreationAllowed: true)
///    .jwtSession('me', 'sshh', usernameLookup)
///    ..allowHttp=true)
///  .build();
///  ```
///
///  Note: this example is a bit convoluted as you don't typically want session
///  creation with basic auth
AuthenticationBuilder builder() => new AuthenticationBuilder();

/// A builder to help with the creation of shelf_auth middleware
class AuthenticationBuilder {
  List<Authenticator> _authenticators = [];
  SessionHandler _sessionHandler;
  bool allowHttp = false;
  bool allowAnonymousAccess = true;

  /// adds a BASIC AUTH authenticator to the list of authenticators
  AuthenticationBuilder basic(UserLookupByUsernamePassword userLookup,
      {bool sessionCreationAllowed: false, bool sessionUpdateAllowed: false}) =>
      authenticator(new BasicAuthenticator(userLookup,
          sessionCreationAllowed: sessionCreationAllowed,
          sessionUpdateAllowed: sessionUpdateAllowed));

  /// adds the given authenticator to the list of authenticators
  AuthenticationBuilder authenticator(Authenticator authenticator) {
    _authenticators.add(authenticator);
    return this;
  }

  /// sets the session handler to be a JWT based handler created from the
  /// provided details
  AuthenticationBuilder jwtSession(
      String issuer, String secret, UserLookupByUsername userLookup,
      {Duration idleTimeout: const Duration(minutes: 30),
      Duration totalSessionTimeout: const Duration(days: 1)}) {
    return sessionHandler(new JwtSessionHandler(issuer, secret, userLookup,
        idleTimeout: idleTimeout, totalSessionTimeout: totalSessionTimeout));
  }

  /// sets the session handler to be the provided handler
  AuthenticationBuilder sessionHandler(SessionHandler sessionHandler) {
    _sessionHandler = sessionHandler;
    return this;
  }

  /// Creates middleware from the provided details
  Middleware build() => authenticate(_authenticators,
      sessionHandler: _sessionHandler,
      allowHttp: allowHttp,
      allowAnonymousAccess: allowAnonymousAccess);
}
