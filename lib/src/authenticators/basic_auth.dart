library shelf_auth.authentication.basic;

import '../authentication.dart';
import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:crypto/crypto.dart';
import '../principal/user_lookup.dart';
import 'package:shelf_exception_response/exception.dart';
import '../preconditions.dart';

/**
 * An [Authenticator] for Basic Authentication (http://tools.ietf.org/html/rfc2617)
 */
class BasicAuthenticator<P extends Principal> extends Authenticator<P> {
  final UserLookupByUsernamePassword<P> userLookup;

  BasicAuthenticator(this.userLookup) {
    ensure(userLookup, isNotNull);
  }

  @override
  Future<Option<AuthenticationContext<P>>> authenticate(Request request) {
    return authorizationHeader(request).flatMap((authHeader) {
      if (authHeader.authScheme != 'Basic') {
        return const None();
      }

      final usernamePasswordStr = _getCredentials(authHeader);

      final usernamePassword = usernamePasswordStr.split(':');

      if (usernamePassword.length != 2) {
        throw new BadRequestException();
      }

      final principalFuture = userLookup(usernamePassword[0],
          usernamePassword[1]);

      return new Some(principalFuture.then((principalOption) =>
          principalOption.map((principal) =>
              new AuthenticationContext(principal))));
    })
    .getOrElse(() => new Future(() => const None()));

  }

  String _getCredentials(AuthorizationHeader authHeader) {
    try {
      return new String.fromCharCodes(
          CryptoUtils.base64StringToBytes(authHeader.credentials));
    } on FormatException catch(e) {
      return '';
    }
  }
}
