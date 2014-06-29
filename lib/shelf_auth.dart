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


  Middleware get middleware => _createHandler;

  Handler _createHandler(Handler innerHandler) {
    return (Request request) => _handle(request, innerHandler);
  }

  Future<Response> _handle(Request request, Handler innerHandler) {
    final Stream<Option<AuthenticationContext>> optAuthContexts =
        new Stream.fromIterable(authenticators).asyncMap((a) =>
            a.authenticate(request));

    final Future<Option<AuthenticationContext>> optAuthFuture =
        optAuthContexts.firstWhere((authOpt) => authOpt.nonEmpty(),
            defaultValue: () => const None());

    final Future<Response> responseFuture =
        optAuthFuture.then((authOpt) =>
            _createResponse(authOpt, request, innerHandler));

    // TODO: errors should likely be in shelf_expection_response types and
    // just throw out of here
    return responseFuture
      .catchError((e) {
        return new Response(401);
      }, test: (e) => e is AuthenticationFailure)
      .catchError((e, stackTrace) {
        print('--- $e');
        print(stackTrace);
        // TODO: let through to shelf_expection_response
        return new Response.internalServerError(body: e.toString());
      });
  }

  Future<Response> _createResponse(
      Option<AuthenticationContext> authContextOpt,
      Request request, Handler innerHandler) {
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
              newFuture(() =>
                  sessionHandler.get().handle(authContext, request, response)))
          : responseFuture;

      return updatedResponseFuture;
    }).getOrElse(() {
        return newFuture(() => new Response(401));
    });
  }
}