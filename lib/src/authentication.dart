// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authentication;

import 'package:shelf/shelf.dart';
import 'package:option/option.dart';
import 'package:logging/logging.dart';
import 'authentication_impl.dart';
import 'core.dart';

export 'core.dart';

final Logger _log = new Logger('shelf_auth.authentication');

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
 * if the resulting [AuthenticatedContext] supports sessions.
 *
 * By default authentication must occur over https and anonymous access is
 * allowed. These can be overridden with the flags [allowHttp] and
 * [allowAnonymousAccess] respectively.
 *
 * Example use
 *
 * ```
 *   var handler = const Pipeline()
        .addMiddleware(exceptionHandler())
        .addMiddleware(authenticate([new BasicAuthenticator(userLookup)]))
        .addHandler((Request request) => new Response.ok("I'm in"));

    io.serve(handler, 'localhost', 8080);
  * ```
 */
Middleware authenticate(Iterable<Authenticator> authenticators,
    {SessionHandler sessionHandler, bool allowHttp: false,
    bool allowAnonymousAccess: true}) => new AuthenticationMiddleware(
    authenticators.toList(growable: false), new Option(sessionHandler),
    allowHttp: allowHttp,
    allowAnonymousAccess: allowAnonymousAccess).middleware;

/**
 * Retrieves the current [AuthenticatedContext] from the [request] if one
 * exists
 */
Option<AuthenticatedContext> getAuthenticatedContext(Request request) {
  return new Option(request.context[SHELF_AUTH_REQUEST_CONTEXT]);
}
