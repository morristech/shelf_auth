// Copyright (c) 2015, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authentication.model;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:http_exception/http_exception.dart';
import 'package:logging/logging.dart';
import 'context.dart';

final Logger _log = new Logger('shelf_auth.authentication.model');

typedef String SessionIdentifierFactory();

/**
 * A class that may establish and / or update a session for the authenticated
 * principal. It has an accompanying [Authenticator] to authenticate session
 * tokens on incoming requests.
 *
 * Implementations must respect the values of
 * [sessionCreationAllowed] and [sessionUpdateAllowed] in the given
 * [AuthenticatedContext]
 */
abstract class SessionHandler<P extends Principal> {
  /// Update the [response] with a session token as appropriate
  Future<Response> handle(
      AuthenticatedContext context, Request request, Response response);

  /// authenticator for session tokens created by the [handle] method
  Authenticator<P> get authenticator;
}

/**
 * An authenticator of Http Requests for *Shelf*
 */
abstract class Authenticator<P extends Principal> {
  /**
   * Authenticates the request returning a Future with one of three outcomes:
   *
   * * [None] to indicate that no authentication credentials exist for this
   * authenticator. Other authenticators can now get their turn to authenticate
   *
   * * [Some] [AuthenticatedContext] when authentication succeeds
   *
   * * An exception if authentication fails (e.g. [UnauthorizedException])
   *
   * Note: *shelf_auth* assumes that the *shelf_exception_handler* package
   * or similar is used to turn exceptions into suitable http responses.
   */
  Future<Option<AuthenticatedContext<P>>> authenticate(Request request);

  bool get readsBody;
}

/// Represents a whitelist for requests
typedef bool RequestWhiteList(Request request);

/// creates a [RequestWhiteList] from an [Iterable] of whitelisted paths
RequestWhiteList requestPathWhiteList(Iterable<String> whitelistedPaths) {
  return (Request request) => whitelistedPaths.contains(request.url.path);
}
