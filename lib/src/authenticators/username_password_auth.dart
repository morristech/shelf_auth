library shelf_auth.authentication.usernamepassword;

import '../authentication.dart';
import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import '../principal/user_lookup.dart';
import 'package:shelf_exception_response/exception.dart';
import '../preconditions.dart';
import 'core.dart';

typedef String ParamExtractor(Request request);

/**
 * An [Authenticator]
 */
class UsernamePasswordAuthenticator<P extends Principal> extends AbstractAuthenticator<P> {
  final UserLookupByUsernamePassword<P> userLookup;
  final ParamExtractor getUsername;
  final ParamExtractor getPassword;

  UsernamePasswordAuthenticator(this.userLookup,
      this.getUsername, this.getPassword,
      { bool sessionCreationAllowed: false,
    bool sessionUpdateAllowed: false })
      : super(sessionCreationAllowed, sessionUpdateAllowed){
    ensure(userLookup, isNotNull);
  }

  @override
  Future<Option<AuthenticationContext<P>>> authenticate(Request request) {
    final username = getUsername(request);
    final password = getPassword(request);
    if (username == null || password == null) {
      throw new UnauthorizedException();
    }

    final principalFuture = userLookup(username, password);

    return principalFuture.then((principalOption) =>
        principalOption.map((principal) =>
            createContext(principal)
    )
    .getOrElse(() => new Future(() => const None())));

  }
}
