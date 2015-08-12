// Copyright (c) 2015, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authentication.model.context;

import 'package:option/option.dart';
import 'package:logging/logging.dart';
import 'package:dart_jwt/src/util.dart';
import 'package:quiver/core.dart';

final Logger _log = new Logger('shelf_auth.authentication.model');

/**
 * Someone or system that can be authenticated
 */
class Principal {
  final String name;

  Principal(this.name) {
    checkNotNull(name);
  }

  String toString() => 'Principal[$name]';
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
  final String sessionIdentifier;

  final DateTime sessionFirstCreated;

  final DateTime sessionLastRefreshed;

  final DateTime noSessionRenewalAfter;

  SessionAuthenticatedContext(P principal, this.sessionIdentifier,
      this.sessionFirstCreated, this.sessionLastRefreshed,
      this.noSessionRenewalAfter, {Option<P> onBehalfOf: const None(),
      bool sessionCreationAllowed: true, bool sessionUpdateAllowed: true})
      : super(principal,
          sessionCreationAllowed: sessionCreationAllowed,
          sessionUpdateAllowed: sessionUpdateAllowed);

  SessionAuthenticatedContext refresh({P principal}) =>
      new SessionAuthenticatedContext(firstNonNull(principal, this.principal),
          sessionIdentifier, sessionFirstCreated, new DateTime.now(),
          noSessionRenewalAfter, onBehalfOf: onBehalfOf,
          // TODO: these properties seem strange in this context. Review
          sessionCreationAllowed: false, sessionUpdateAllowed: true);
}
