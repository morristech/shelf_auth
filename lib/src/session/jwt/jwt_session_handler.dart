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
import '../session_core.dart';
import 'package:shelf_auth/src/context.dart';
import 'package:dart_jwt/dart_jwt.dart';

class JwtSessionHandler<P extends Principal, CS extends SessionClaimSet>
    implements SessionHandler<P, CS> {
  final String issuer;
  final String secret;
  final Duration idleTimeout;
  final Duration totalSessionTimeout;
  final JwtSessionAuthenticator<P, CS> authenticator;
  final SessionIdentifierFactory createSessionId;
  final JwtCodec<CS> jwtCodec;

  JwtSessionHandler(
      String issuer, String secret, UserLookupByUsername<P> userLookup,
      {Duration idleTimeout: const Duration(minutes: 30),
      Duration totalSessionTimeout: const Duration(days: 1),
      SessionIdentifierFactory createSessionId: defaultCreateSessionIdentifier,
      JwtCodec<CS> jwtCodec})
      : this.custom(
          issuer, secret, (CS claimsSet) => userLookup(claimsSet.subject),
          idleTimeout: idleTimeout,
          totalSessionTimeout: totalSessionTimeout,
          createSessionId: createSessionId);

  JwtSessionHandler.custom(
      this.issuer, String secret, UserLookupBySessionClaimSet<P, CS> userLookup,
      {this.idleTimeout: const Duration(minutes: 30),
      this.totalSessionTimeout: const Duration(days: 1),
      this.createSessionId: defaultCreateSessionIdentifier,
      JwtCodec<CS> jwtCodec})
      : this.secret = secret,
        this.authenticator = new JwtSessionAuthenticator<P, CS>.custom(
            userLookup, secret,
            tokenDecoder: (String jwtToken,
                    {JwsValidationContext validationContext}) =>
                _jwtCodec(jwtCodec).decoder.convert(jwtToken)),
        this.jwtCodec = _jwtCodec(jwtCodec) {
    ensure(issuer, isNotNull);
    ensure(this.secret, isNotNull);
    ensure(idleTimeout, isNotNull);
    ensure(createSessionId, isNotNull);
    ensure(this.jwtCodec, isNotNull);
  }

  static JwtCodec _jwtCodec(JwtCodec jwtCodec) =>
      jwtCodec != null ? jwtCodec : jwtSessionCodec;

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

    final claimSet = createSessionClaim(
        context.principal.name, createSessionId(), newIdleTimeout);

//    _log.finest('created claimSet: \n${claimSet.toJson()}');

    final jwt = new JsonWebToken.jws(
        claimSet, new JwaSymmetricKeySignatureContext(secret));

    final sessionToken = jwtCodec.encode(jwt);

    return addAuthorizationHeader(response,
        new AuthorizationHeader(JWT_SESSION_AUTH_SCHEME, sessionToken));
  }

  CS createSessionClaim(
      String subject, String sessionIdentifier, Duration newIdleTimeout) {
    return new SessionClaimSet.std(issuer, subject, sessionIdentifier,
        idleTimeout: newIdleTimeout, totalSessionTimeout: totalSessionTimeout);
  }

  SessionAuthenticatedContext _getSessionContext(AuthenticatedContext context) {
    final now = new DateTime.now();

    return context is SessionAuthenticatedContext
        ? context
        : new SessionAuthenticatedContext(context.principal, createSessionId(),
            now, now, now.add(totalSessionTimeout));
  }
}
