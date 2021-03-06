// Copyright (c) 2015, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authentication.impl;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'util.dart';
import 'package:http_exception/http_exception.dart';
import 'package:logging/logging.dart';
import 'core.dart';
import 'zone_context.dart';
import 'context.dart';

const String SHELF_AUTH_REQUEST_CONTEXT = 'shelf.auth.context';

final Logger _log = new Logger('shelf_auth.authentication.internal');

/**
 * [Middleware] for performing authentication using a provided list of
 * [Authenticator]s.
 *
 * An optional [SessionHandler] can be provided to create /
 * update a session as a result (e.g. by setting a cookie or token etc).
 * The [sessionHandler]s associated [Authenticator] will be
 * the first authenticator called when authenticating requests
 *
 * If no [SessionHandler] is provided then no session will be created if none
 * currently exists and no changes will be made to an existing one if one does
 * exist
 *
 * By default authentication is only allowed via HTTPS to avoid eavesdropping of
 * security credentials. This can be overriden by setting [allowHttp] to true.
 *
 * By default if no authenticators either return a successful authentication or
 * throw an exception, the request is allowed to continue as anonymous (guest).
 * This can be overridden by setting [allowAnonymousAccess] to false.
 */
class AuthenticationMiddleware {
  final List<Authenticator> authenticators;
  final Option<SessionHandler> sessionHandler;
  final bool allowHttp;
  final bool allowAnonymousAccess;

  AuthenticationMiddleware(
      List<Authenticator> authenticators, Option<SessionHandler> sessionHandler,
      {this.allowHttp: false, this.allowAnonymousAccess: true})
      : this.authenticators = (sessionHandler is Some ? ([]
          ..add(sessionHandler.get().authenticator)
          ..addAll(authenticators)) : authenticators),
        this.sessionHandler = sessionHandler;

  Middleware get middleware => _createHandler;

  Handler _createHandler(Handler innerHandler) {
    return (Request request) => _handle(request, innerHandler);
  }

  Future<Response> _handle(Request request, Handler innerHandler) {
    final Stream<Option<AuthenticatedContext>> optAuthContexts =
        new Stream.fromIterable(authenticators)
            .asyncMap((a) => a.authenticate(request));

    final Future<Option<AuthenticatedContext>> optAuthFuture = optAuthContexts
        .firstWhere((authOpt) => authOpt is Some,
            orElse: () => const None());

    final Future<Response> responseFuture = optAuthFuture
        .then((authOpt) => _createResponse(authOpt, request, innerHandler));

    return responseFuture;
  }

  Future<Response> _createResponse(Option<AuthenticatedContext> authContextOpt,
      Request request, Handler innerHandler) {
    return authContextOpt.map((authContext) {
      if (!allowHttp && request.requestedUri.scheme != 'https') {
        _log.finer('denying access over http');
        throw new UnauthorizedException();
      }

      final bodyConsumed = authenticators.any((a) => a.readsBody);
      final initialRequest = bodyConsumed
          ? new Request(request.method, request.requestedUri,
              protocolVersion: request.protocolVersion,
              headers: request.headers,
              url: request.url,
              handlerPath: request.handlerPath,
              body: null,
              context: request.context)
          : request;

      final newRequest = initialRequest.change(
          context: {SHELF_AUTH_REQUEST_CONTEXT: authContext});
      final responseFuture = new Future.sync(
          () => _runInNewZone(innerHandler, newRequest, authContext));

      final bool canHandleSession = sessionHandler is Some &&
          (authContext.sessionCreationAllowed ||
              authContext.sessionUpdateAllowed);

      final updatedResponseFuture = canHandleSession
          ? responseFuture.then((response) => newFuture(() =>
              sessionHandler.get().handle(authContext, request, response)))
          : responseFuture;

      return updatedResponseFuture;
    }).getOrElse(() {
      if (!allowAnonymousAccess) {
        _log.finer('denying unauthenticated access');
        throw new UnauthorizedException();
      }
      return new Future.sync(() => innerHandler(request));
    });
  }
}

_runInNewZone(
    Handler innerHandler, Request request, AuthenticatedContext authContext) {
  return runInNewZone(authContext, () => innerHandler(request));
}
