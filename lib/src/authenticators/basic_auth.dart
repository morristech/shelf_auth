library shelf_auth.authentication.basic;

import '../authentication.dart';
import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:crypto/crypto.dart';

class BasicAuthenticator<P extends Principal> extends Authenticator<P> {
  final UserLookupByUsernamePassword<P> userLookup;

  BasicAuthenticator(this.userLookup);

  @override
  Future<Option<AuthenticationContext<P>>> authenticate(Request request) {
    return authorizationHeader(request).flatMap((authHeader) {
      if (authHeader.realm != 'Basic') {
        return const None();
      }

      final usernamePasswordStr = _getCredentials(authHeader);

      final usernamePassword = usernamePasswordStr.split(':');

      if (usernamePassword.length != 2) {
        return const None();
      }

      final principalFuture = userLookup.lookup(usernamePassword[0],
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

// TODO: move elsewhere as usable beyond basic
abstract class UserLookupByUsernamePassword<P extends Principal> {

  Future<Option<P>> lookup(String username, String password);

}