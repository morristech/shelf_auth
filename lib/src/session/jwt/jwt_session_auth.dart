library shelf_auth.authentication.session.jwt;

import '../../authentication.dart';
import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import '../../principal/user_lookup.dart';
import 'jwt_session.dart';
import 'package:dart_jwt/dart_jwt.dart';
import 'package:shelf_exception_response/exception.dart';
import '../../preconditions.dart';
import '../../util.dart';
import '../../authenticators/core.dart';


/**
 * An [Authenticator] for Shelf Auth Jwt Session Token
 */
class JwtSessionAuthenticator<P extends Principal> extends
      AbstractAuthenticator<P> {
  final UserLookupByUsername<P> userLookup;
  final String secret;

  JwtSessionAuthenticator(this.userLookup, this.secret,
      { bool sessionCreationAllowed: false, bool sessionUpdateAllowed: true })
      : super(sessionCreationAllowed, sessionUpdateAllowed) {
    ensure(userLookup, isNotNull);
    ensure(secret, isNotNull);
  }

  @override
  Future<Option<AuthenticationContext<P>>> authenticate(Request request) {
    final authHeaderOpt = authorizationHeader(request, JWT_SESSION_AUTH_SCHEME);
    return authHeaderOpt.map((authHeader) {

      final sessionJwtToken = authHeader.credentials;

      final sessionJwt = decodeSessionToken(sessionJwtToken);
      final violations = sessionJwt.validate(
          new JwtValidationContext.withSharedSecret(secret));

      if (violations.isNotEmpty) {
        // TODO: include error details
        throw new UnauthorizedException();
      }

      final SessionClaimSet claimSet = sessionJwt.claimSet;
      final principalFuture = userLookup(claimSet.subject);

      return principalFuture.then((principalOption) =>
          principalOption.map((principal) =>
              new SessionAuthenticationContext(principal,
                  claimSet.issuedAt, new DateTime.now(),
                  claimSet.totalSessionExpiry)));
    })
    .getOrElse(() => new Future(() => const None()));

  }

}
