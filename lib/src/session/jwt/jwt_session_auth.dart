// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authentication.session.jwt;

import '../../authentication.dart';
import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import '../../principal/user_lookup.dart';
import 'jwt_session.dart';
import 'package:dart_jwt/dart_jwt.dart';
import 'package:http_exception/http_exception.dart';
import '../../preconditions.dart';
import '../../util.dart';
import '../../authenticators/core.dart';
import 'package:shelf_auth/src/context.dart';

/**
 * An [Authenticator] for Shelf Auth Jwt Session Token
 */
class JwtSessionAuthenticator<P extends Principal, CS extends SessionClaimSet>
    extends AbstractAuthenticator<P> {
  final UserLookupBySessionClaimSet<P, CS> userLookup;
  final SessionTokenDecoder<CS> tokenDecoder;
  final String secret;

  JwtSessionAuthenticator(UserLookupByUsername userLookup, String secret,
      {bool sessionCreationAllowed: false, bool sessionUpdateAllowed: true})
      : this.custom((CS claimsSet) => userLookup(claimsSet.subject), secret,
            sessionCreationAllowed: sessionCreationAllowed,
            sessionUpdateAllowed: sessionUpdateAllowed);

  JwtSessionAuthenticator.custom(this.userLookup, this.secret,
      {bool sessionCreationAllowed: false,
      bool sessionUpdateAllowed: true,
      this.tokenDecoder: decodeSessionToken})
      : super(sessionCreationAllowed, sessionUpdateAllowed) {
    ensure(userLookup, isNotNull);
    ensure(secret, isNotNull);
    ensure(tokenDecoder, isNotNull);
  }

  @override
  Future<Option<AuthenticatedContext<P>>> authenticate(Request request) {
    final authHeaderOpt = authorizationHeader(request, JWT_SESSION_AUTH_SCHEME);
    return authHeaderOpt.map((authHeader) async {
      final sessionJwtToken = authHeader.credentials;

      final sessionJwt = tokenDecoder(sessionJwtToken);
      final violations = sessionJwt
          .validate(new JwtValidationContext.withSharedSecret(secret));

      if (violations.isNotEmpty) {
        // TODO: include error details
        throw new UnauthorizedException();
      }

      final CS claimSet = sessionJwt.claimSet;
      final principalOption = await userLookup(claimSet);

      return principalOption.map((principal) => new SessionAuthenticatedContext(
          principal,
          claimSet.sessionIdentifier,
          claimSet.issuedAt,
          new DateTime.now(),
          claimSet.totalSessionExpiry));
    }).getOrElse(() => new Future(() => const None()));
  }
}
