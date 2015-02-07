// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.session.jwt.handler;

import 'jwt_session.dart';
import 'jwt_session_auth.dart';
import '../../authentication.dart';
import 'package:shelf/shelf.dart';
import '../../preconditions.dart';
import '../../util.dart';
import '../../principal/user_lookup.dart';

class JwtSessionHandler<P extends Principal> implements SessionHandler<P> {
  final String issuer;
  final String secret;
  final Duration idleTimeout;
  final Duration totalSessionTimeout;
  final JwtSessionAuthenticator<P> authenticator;

  JwtSessionHandler(
      this.issuer, String secret, UserLookupByUsername<P> userLookup,
      {this.idleTimeout: const Duration(minutes: 30),
      this.totalSessionTimeout: const Duration(days: 1)})
      : this.secret = secret,
        this.authenticator = new JwtSessionAuthenticator<P>(
            userLookup, secret) {
    ensure(issuer, isNotNull);
    ensure(secret, isNotNull);
    ensure(idleTimeout, isNotNull);
  }

  @override
  Response handle(
      AuthenticatedContext context, Request request, Response response) {
    final now = new DateTime.now();

    final sessionContext = _getSessionContext(context);
    final noSessionRenewalAfter = sessionContext.noSessionRenewalAfter;

    if (noSessionRenewalAfter.isBefore(now)) {
      return response;
    }

    final remainingSessionTime = noSessionRenewalAfter.difference(now);

    final newIdleTimeout = idleTimeout <= remainingSessionTime
        ? idleTimeout
        : remainingSessionTime;

    final sessionToken = createSessionToken(
        secret, issuer, context.principal.name,
        idleTimeout: newIdleTimeout, totalSessionTimeout: remainingSessionTime);

    return addAuthorizationHeader(response,
        new AuthorizationHeader(JWT_SESSION_AUTH_SCHEME, sessionToken));
  }

  SessionAuthenticatedContext _getSessionContext(AuthenticatedContext context) {
    final now = new DateTime.now();

    return context is SessionAuthenticatedContext
        ? context
        : new SessionAuthenticatedContext(
            context.principal, now, now, now.add(totalSessionTimeout));
  }
}
