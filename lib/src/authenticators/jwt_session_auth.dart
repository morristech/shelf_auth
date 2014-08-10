library shelf_auth.authentication.session.jwt;

import '../authentication.dart';
import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import '../principal/user_lookup.dart';
import '../session/jwt/jwt_session.dart';
import 'package:dart_jwt/dart_jwt.dart';
import 'package:shelf_exception_response/exception.dart';
import '../preconditions.dart';

const String _JWT_SESSION_AUTH_SCHEME = 'ShelfAuthJwtSession';

/**
 * An [Authenticator] for Shelf Auth Jwt Session Token
 */
class JwtSessionAuthenticator<P extends Principal> extends Authenticator<P> {
  final UserLookupByUsername<P> userLookup;
  final String secret;

  JwtSessionAuthenticator(this.userLookup, this.secret) {
    ensure(userLookup, isNotNull);
    ensure(secret, isNotNull);
  }

  @override
  Future<Option<AuthenticationContext<P>>> authenticate(Request request) {
    return authorizationHeader(request).flatMap((authHeader) {
      if (authHeader.authScheme != _JWT_SESSION_AUTH_SCHEME) {
        return const None();
      }

      final sessionJwtToken = authHeader.credentials;

      final sessionJwt = decodeSessionToken(sessionJwtToken);
      final violations = sessionJwt.validate(
          new JwtValidationContext.withSharedSecret(secret));

      if (violations.isNotEmpty) {
        // TODO: include error details
        throw new UnauthorizedException();
      }

      final principalFuture = userLookup(sessionJwt.claimSet.subject);

      return new Some(principalFuture.then((principalOption) =>
          principalOption.map((principal) =>
              new AuthenticationContext(principal))));
    })
    .getOrElse(() => new Future(() => const None()));

  }

}
