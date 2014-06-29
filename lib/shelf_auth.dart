library shelf_auth;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'src/util.dart';

const String _SHELF_AUTH_REQUEST_CONTEXT = 'shelf.auth.context';

Middleware authenticationMiddleware(Iterable<Authenticator> authenticators,
                                    [ SessionHandler sessionHandler ]) =>
    new AuthenticationMiddleware(authenticators.toList(growable: false),
        new Option(sessionHandler))
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

  /// contains the [Principal] that the actions are being performed on behalf of
  /// if applicable
  final Option<P> onBehalfOf;

  /// true if a session may be established as a result of this authentication
  final bool sessionCreationAllowed;

  /// true if the authentication details may be updated in the session as
  /// a result of this authentication
  final bool sessionUpdateAllowed;

  AuthenticationContext(this.principal,
      { this.onBehalfOf: const None(),
        this.sessionCreationAllowed: true, this.sessionUpdateAllowed: true });
}

class AuthenticationFailure {

}

abstract class SessionHandler {
  Response handle(AuthenticationContext context,
                  Request request, Response response);
}


abstract class Authenticator<P extends Principal> {
  Future<Option<AuthenticationContext<P>>> authenticate(Request request);
}

class AuthenticationMiddleware {
  final List<Authenticator> authenticators;
  final Option<SessionHandler> sessionHandler;

  AuthenticationMiddleware(this.authenticators, this.sessionHandler);

  Handler _createHandler(Handler innerHandler) {
    return (Request request) {
      final Iterable<Future<Option<AuthenticationContext>>> authFutures =
          authenticators.map((a) => a.authenticate(request));

      final Stream<Future<Option<AuthenticationContext>>> streamFutures =
          new Stream.fromIterable(authFutures);

      final Stream<Option<AuthenticationContext>> streamAuthOpts =
          streamFutures.asyncExpand((future) => future.asStream());

      final Stream<Option<AuthenticationContext>> singleOptStream =
          streamAuthOpts.skipWhile((authOpt) => authOpt.isEmpty())
          .take(1);

      final Stream<Response> singleResponseStream =
          singleOptStream.asyncMap((authContextOpt) {
        return authContextOpt.map((authContext) {
          final newRequest = request.change(context: {
            _SHELF_AUTH_REQUEST_CONTEXT: authContext
          });
          final responseFuture = syncFuture(() => innerHandler(newRequest));

          final bool canHandleSession = sessionHandler.nonEmpty() &&
              (authContext.sessionCreationAllowed ||
                  authContext.sessionUpdateAllowed);

          final updatedResponseFuture = canHandleSession ?
              responseFuture.then((response) =>
                  sessionHandler.get().handle(authContext, request, response))
              : responseFuture;

          return updatedResponseFuture;
        }).getOrElse(() {
          return new Response(401);
        });
      });

      return singleResponseStream.firstWhere((_) => true,
          defaultValue: () => new Response(401))
        .catchError((e) {
          return new Response(401);
        }, test: (e) => e is AuthenticationFailure)
        .catchError((e, stackTrace) {
          print('--- $e');
          print(stackTrace);
          // TODO: let through to shelf_expection_response
          return new Response.internalServerError(body: e);
        });
    };
  }

  Middleware get middleware => _createHandler;
}