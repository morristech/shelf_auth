library shelf_auth;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';

const String _SHELF_AUTH_REQUEST_CONTEXT = 'shelf.auth.context';

Middleware authenticationMiddleware(Iterable<Authenticator> authenticators) =>
    new AuthenticationMiddleware(authenticators.toList(growable: false))
      .middleware;

Option<AuthenticationContext> getAuthenticationContext(Request request) {
  return new Option(request.context[_SHELF_AUTH_REQUEST_CONTEXT]);
}

class Principal {
  final String name;

  Principal(this.name);
}

class AuthenticationContext<P extends Principal> {
  final P principal;

  AuthenticationContext(this.principal);
}

class AgentAuthenticationContext<P extends Principal, A extends Principal>
    extends AuthenticationContext<P> {
  final A onBehalfOf;

  AgentAuthenticationContext(P principal, this.onBehalfOf)
          : super(principal);
}

class AuthenticationFailure {

}


abstract class Authenticator<P extends Principal> {
  Future<Option<AuthenticationContext<P>>> authenticate(Request request);
}

class AuthenticationMiddleware {
  final List<Authenticator> authenticators;

  AuthenticationMiddleware(this.authenticators);

  Handler _createHandler(Handler innerHandler) {
    return (Request request) {
      final Iterable<Future<Option<AuthenticationContext>>> authFutures =
          authenticators.map((a) => a.authenticate(request));

      final Stream<Future<Option<AuthenticationContext>>> streamFutures =
          new Stream.fromIterable(authFutures);

      final Stream<Option<AuthenticationContext>> streamAuthOpts =
          streamFutures.asyncExpand((future) => future.asStream());

      // TODO: firstWhere will return a future error if no auths pass => handle
      final Future<AuthenticationContext> authContextFuture =
          streamAuthOpts.firstWhere((authOpt) => authOpt.nonEmpty());

      return authContextFuture.then((authContext) {
        final newRequest = request.change(context: {
          _SHELF_AUTH_REQUEST_CONTEXT: authContext
        });
        return innerHandler(newRequest);

      }).catchError((e, stackTrace) {
        print(e);
        print(stackTrace);
        /* TODO: either no auths match or one has failed
         * return an error Response
         */
      });
    };
  }

  Middleware get middleware => _createHandler;
}