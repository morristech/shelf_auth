library shelf_auth.authentication;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'util.dart';
import 'package:shelf_exception_response/exception.dart';

const String _SHELF_AUTH_REQUEST_CONTEXT = 'shelf.auth.context';

/**
 * Creates *Shelf* middleware for performing authentication and optionally
 * creating / updating a session.
 *
 * Supports a chain of [Authenticator]s where the first to either succeed or
 * throw wins.
 *
 * Supports custom [Authenticator]s in addition to some standard out of the box
 * implementations.
 *
 * The [SessionHandler] if provided will be invoked on successful authentication
 * if the resulting [AuthenticationContext] supports sessions.
 *
 * Example use
 *
 * ```
 *   var handler = const Pipeline()
        .addMiddleware(exceptionResponse())
        .addMiddleware(authenticate([new BasicAuthenticator(userLookup)]))
        .addHandler((Request request) => new Response.ok("I'm in"));

    io.serve(handler, 'localhost', 8080);
  * ```
 */
Middleware authenticate(Iterable<Authenticator> authenticators,
                                    [ SessionHandler sessionHandler ]) =>
    new AuthenticationMiddleware(authenticators.toList(growable: false),
        new Option(sessionHandler))
      .middleware;

/**
 * Retrieves the current [AuthenticationContext] from the [request] if one
 * exists
 */
Option<AuthenticationContext> getAuthenticationContext(Request request) {
  return new Option(request.context[_SHELF_AUTH_REQUEST_CONTEXT]);
}

/**
 * Someone or system that can be authenicated
 */
class Principal {
  final String name;

  Principal(this.name);
}

/**
 * A context representing a successful authentication as a particular
 * [Principal].
 *
 * Supports optionally authenticating as one principal that is acting [onBehalfOf]
 * another. Typically that would be a system acting on behalf of a real user.
 *
 * If [sessionCreationAllowed] is true then a [SessionHandler] will be allowed
 * to create a new session based on this context.
 *
 * If [sessionUpdateAllowed] is true then a [SessionHandler] will be allowed
 * to update the details in an existing session, including extending timeouts,
 * updating the details about the authenticated principal etc.
 *
 * Note: [sessionCreationAllowed] and [sessionUpdateAllowed] are typically false
 * for server to server interaction, but true for user to system interaction
 *
 */
// TODO: AuthenticationContext sounds more like something you pass into an
// authenticator than something that you get out
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

/**
 * An [AuthenticationContext] established by authenticating via a session
 * token mechanism
 */
class SessionAuthenticationContext<P extends Principal>
        extends AuthenticationContext<P> {
  final DateTime sessionFirstCreated;

  final DateTime sessionLastRefreshed;

  final DateTime noSessionRenewalAfter;

  SessionAuthenticationContext(P principal,
      this.sessionFirstCreated, this.sessionLastRefreshed,
          this.noSessionRenewalAfter,
      { Option<P> onBehalfOf: const None(),
         bool sessionCreationAllowed: true, bool sessionUpdateAllowed: true })
      : super(principal, sessionCreationAllowed: sessionCreationAllowed,
            sessionUpdateAllowed: sessionUpdateAllowed);
}


/**
 * A class that may establish and / or update a session for the authenticated
 * principal.
 *
 * Implementations must respect the values of
 * [sessionCreationAllowed] and [sessionUpdateAllowed] in the given
 * [AuthenticationContext]
 */
abstract class SessionHandler {
  Response handle(AuthenticationContext context,
                  Request request, Response response);
}

/**
 * An authenticator of Http Requests for *Shelf*
 */
abstract class Authenticator<P extends Principal> {
  /**
   * Authenticates the request returning a Future with one of three outcomes:
   *
   * * [None] to indicate that no authentication credentials exist for this
   * authenticator. Other authenicators can now get their turn to authenticate
   *
   * * [Some] [AuthenticationContext] when authentication succeeds
   *
   * * An exception if authentication fails (e.g. [UnauthorizedException])
   *
   * Note: *shelf_auth* assumes that the *shelf_exception_response* package
   * or similar is used to turn exceptions into suitable http responses.
   */
  Future<Option<AuthenticationContext<P>>> authenticate(Request request);
}

/**
 * [Middleware] for performing authentication using a provided list of
 * [Authenticator]s.
 *
 * An optional [SessionHandler] can be provided to create /
 * update a session as a result (e.g. by setting a cookie or token etc).
 *
 * If no [SessionHandler] is provided then no session will be created if none
 * currently exists and no changes will be made to an existing one if one does
 * exist
 */
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

    return responseFuture;
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
      return syncFuture(() => innerHandler(request));
    });
  }
}

