// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_auth/shelf_auth.dart';
import 'package:shelf_exception_response/exception_response.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:logging/logging.dart';

void main() {
  Logger.root.level = Level.FINER;
  Logger.root.onRecord.listen((lr) {
    print('${lr.time} ${lr.level} ${lr.message}');
  });

  var authenticationMiddleware = (builder()
      .authenticator(new FriendlyAuthenticator())..allowHttp = true).build();

  var authorisationMiddleware = (authorisationBuilder()
      .sameOrigin()
      .principalWhitelist((Principal p) => p.name == 'fred')).build();

  var handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(exceptionResponse())
      .addMiddleware(authenticationMiddleware)
      .addMiddleware(authorisationMiddleware)
      .addHandler((Request request) => new Response.ok("I'm in with "
          "${getAuthenticatedContext(request).map((ac) => ac.principal.name)}\n"));

  io.serve(handler, 'localhost', 8080).then((server) {
    print('Serving at http://${server.address.host}:${server.port}');
  });

  // try with curl -i  'http://localhost:8080' -H 'referer: http://localhost/foo'
  // and you should get in
  // but if you omit or change the referer you will be denied
}

class FriendlyAuthenticator extends Authenticator {
  bool readsBody = false;

  @override
  Future<Option<AuthenticatedContext>> authenticate(Request request) {
    return new Future.value(
        new Some(new AuthenticatedContext(new Principal("fred"))));
  }
}

