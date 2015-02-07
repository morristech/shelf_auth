// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisation.impl;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'util.dart';
import 'package:shelf_exception_response/exception.dart';
import 'package:logging/logging.dart';
import 'core.dart';
import 'authorisation.dart';
import 'zone_context.dart';

final Logger _log = new Logger('shelf_auth.authorisation.internal');

/**
 * [Middleware] for performing authorisation using a provided list of
 * [Authoriser]s.
 *
 */
class AuthorisationMiddleware {
  final List<Authoriser> authorisers;

  AuthorisationMiddleware(this.authorisers);

  Middleware get middleware => _createHandler;

  Handler _createHandler(Handler innerHandler) {
    return (Request request) => _handle(request, innerHandler);
  }

  Future<Response> _handle(Request request, Handler innerHandler) {
    final Stream<bool> isAuthorisedResults =
        new Stream.fromIterable(authorisers)
            .asyncMap((Authoriser a) => a.isAuthorised(request));

    final Future<bool> isAuthorisedFuture = isAuthorisedResults.every((b) => b);

    return isAuthorisedFuture.then(
        (isAuthorised) => _createResponse(isAuthorised, request, innerHandler));
  }

  Future<Response> _createResponse(
      bool isAuthorised, Request request, Handler innerHandler) {
    if (!isAuthorised) {
      throw new ForbiddenException();
    }

    return new Future.sync(() => innerHandler(request));
  }
}
