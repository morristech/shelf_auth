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
import 'dart:async';

typedef Future<CS> SessionClaimFactory<P extends Principal, CS extends SessionClaimSet>(
    String issuer, P subject, String sessionIdentifier, Duration idleTimeout,
    Duration totalSessionTimeout);

class JwtSessionHandler<P extends Principal, CS extends SessionClaimSet>
    implements SessionHandler<P> {
  final String issuer;
  final String secret;
  final Duration idleTimeout;
  final Duration totalSessionTimeout;
  final JwtSessionAuthenticator<P, CS> authenticator;
  final SessionIdentifierFactory createSessionId;
  final JwtCodec<CS> jwtCodec;
  final SessionClaimFactory<P, CS> sessionClaimFactory;

  JwtSessionHandler(
      String issuer, String secret, UserLookupByUsername<P> userLookup,
      {Duration idleTimeout: const Duration(minutes: 30),
      Duration totalSessionTimeout: const Duration(days: 1),
      SessionIdentifierFactory createSessionId: defaultCreateSessionIdentifier,
      JwtCodec<CS> jwtCodec})
      : this.custom(issuer, secret,
          (CS claimsSet) => userLookup(claimsSet.subject), (String issuer,
                  P principal, String sessionIdentifier, Duration idleTimeout,
                  Duration totalSessionTimeout) async =>
              await new SessionClaimSet.create(issuer, principal.name,
                  idleTimeout: idleTimeout,
                  totalSessionTimeout: totalSessionTimeout,
                  sessionIdentifier: sessionIdentifier),
          idleTimeout: idleTimeout,
          totalSessionTimeout: totalSessionTimeout,
          createSessionId: createSessionId);

  JwtSessionHandler.custom(this.issuer, String secret,
      UserLookupBySessionClaimSet<P, CS> userLookup, this.sessionClaimFactory,
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
    ensure(sessionClaimFactory, isNotNull);
  }

  static JwtCodec _jwtCodec(JwtCodec jwtCodec) =>
      jwtCodec != null ? jwtCodec : jwtSessionCodec;

  @override
  Future<Response> handle(
      AuthenticatedContext context, Request request, Response response) async {
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

    final claimSet = await createSessionClaim(
        context.principal, createSessionId(), newIdleTimeout);

//    _log.finest('created claimSet: \n${claimSet.toJson()}');

    final jwt = new JsonWebToken.jws(
        claimSet, new JwaSymmetricKeySignatureContext(secret));

    final sessionToken = jwtCodec.encode(jwt);

    return addAuthorizationHeader(response,
        new AuthorizationHeader(JWT_SESSION_AUTH_SCHEME, sessionToken));
  }

  Future<CS> createSessionClaim(
      P principal, String sessionIdentifier, Duration newIdleTimeout) {
    return sessionClaimFactory(issuer, principal, sessionIdentifier,
        newIdleTimeout, totalSessionTimeout);
  }

  SessionAuthenticatedContext _getSessionContext(AuthenticatedContext context) {
    final now = new DateTime.now();

    return context is SessionAuthenticatedContext
        ? context
        : new SessionAuthenticatedContext(context.principal, createSessionId(),
            now, now, now.add(totalSessionTimeout));
  }
}
