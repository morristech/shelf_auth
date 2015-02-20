// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authentication.model;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:shelf_exception_response/exception.dart';
import 'package:logging/logging.dart';

final Logger _log = new Logger('shelf_auth.authentication.model');

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
class AuthenticatedContext<P extends Principal> {
  final P principal;

  /// contains the [Principal] that the actions are being performed on behalf of
  /// if applicable
  final Option<P> onBehalfOf;

  /// true if a session may be established as a result of this authentication
  final bool sessionCreationAllowed;

  /// true if the authentication details may be updated in the session as
  /// a result of this authentication
  final bool sessionUpdateAllowed;

  AuthenticatedContext(this.principal, {this.onBehalfOf: const None(),
      this.sessionCreationAllowed: true, this.sessionUpdateAllowed: true});
}

/**
 * An [AuthenticatedContext] established by authenticating via a session
 * token mechanism
 */
class SessionAuthenticatedContext<P extends Principal>
    extends AuthenticatedContext<P> {
  final DateTime sessionFirstCreated;

  final DateTime sessionLastRefreshed;

  final DateTime noSessionRenewalAfter;

  SessionAuthenticatedContext(P principal, this.sessionFirstCreated,
      this.sessionLastRefreshed, this.noSessionRenewalAfter,
      {Option<P> onBehalfOf: const None(), bool sessionCreationAllowed: true,
      bool sessionUpdateAllowed: true})
      : super(principal,
          sessionCreationAllowed: sessionCreationAllowed,
          sessionUpdateAllowed: sessionUpdateAllowed);
}

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
  Response handle(
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
   * Note: *shelf_auth* assumes that the *shelf_exception_response* package
   * or similar is used to turn exceptions into suitable http responses.
   */
  Future<Option<AuthenticatedContext<P>>> authenticate(Request request);

  bool get readsBody;
}
