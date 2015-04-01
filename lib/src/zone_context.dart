// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.context.zone;

import 'dart:async';
import 'package:option/option.dart';
import 'package:shelf_auth/src/context.dart';

const Symbol SHELF_AUTH_ZONE_CONTEXT = #shelf.auth.context;

/**
 * Retrieves the current [AuthenticatedContext] from the current [Zone] if one
 * exists
 */
Option<AuthenticatedContext> authenticatedContext() =>
    new Option(Zone.current[SHELF_AUTH_ZONE_CONTEXT]);

/// Runs the given [body] in a new [Zone] with the given [AuthenticatedContext]
runInNewZone(AuthenticatedContext authContext, body()) {
  var response;

  runZoned(() {
    response = body();
  }, zoneValues: <Symbol, Object>{SHELF_AUTH_ZONE_CONTEXT: authContext});

  return response;
}
