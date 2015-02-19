// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisation;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:logging/logging.dart';
import 'authorisation_impl.dart';
export 'core.dart';

final Logger _log = new Logger('shelf_auth.authorisation');

/**
 * Creates *Shelf* middleware for performing authorisation.
 *
 * Supports a chain of [Authoriser]s where access will be denied if any [Authoriser]
 * denies access (returns false).
 *
 * If access is denied then a [ForbiddenException] will be thrown if there is
 * an authenticated user, or [UnauthorizedException] if there isn't.
 * It is recommended to use
 * together with the [shelf_exception_response](https://pub.dartlang.org/packages/shelf_exception_response)
 * package or similar to convert exceptions into appropriate Http response
 *
 * Supports custom [Authoriser]s in addition to some standard out of the box
 * implementations.
 *
 * Example use
 *
 *     var handler = const Pipeline()
 *       .addMiddleware(exceptionResponse())
 *       .addMiddleware((authorisationBuilder()
 *           .sameOrigin()
 *           .principalWhitelist((p) => p.name == 'fred')
 *         .build()))
 *       .addHandler((Request request) => new Response.ok("I'm in"));
 *
 *     io.serve(handler, 'localhost', 8080);
 */
Middleware authorise(Iterable<Authoriser> authorisers) =>
    new AuthorisationMiddleware(authorisers.toList(growable: false)).middleware;

/**
 * An authoriser of Http Requests for *Shelf*
 */
abstract class Authoriser {
  /**
   * Performs authorisation checks for Shelf Http Requests.
   *
   * Returns true if the request is authorised and false if it is denied.
   */
  Future<bool> isAuthorised(Request request);
}
