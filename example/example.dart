// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_auth/shelf_auth.dart';
import 'package:shelf_exception_handler/shelf_exception_handler.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:logging/logging.dart';
import 'package:http_exception/http_exception.dart';

void main() {
  Logger.root.level = Level.FINER;
  Logger.root.onRecord.listen((lr) {
    print('${lr.time} ${lr.level} ${lr.message}');
  });

  var authMiddleware = authenticate(
      [new BasicAuthenticator(testLookup), new RandomAuthenticator()],
      // allow http for testing with curl. Don't do in production
      allowHttp: true);

  var handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(exceptionHandler())
      .addMiddleware(authMiddleware)
      .addHandler((Request request) => new Response.ok("I'm in with "
          "${getAuthenticatedContext(request).map((ac) => ac.principal.name)}\n"));

  io.serve(handler, 'localhost', 8080).then((server) {
    print('Serving at http://${server.address.host}:${server.port}');
  });
}

class RandomAuthenticator extends Authenticator {
  bool approve = true;
  bool readsBody = false;

  @override
  Future<Option<AuthenticatedContext>> authenticate(Request request) {
    approve = !approve;

    return approve
        ? new Future.value(
            new Some(new AuthenticatedContext(new Principal("fred"))))
        : new Future.error(new UnauthorizedException());
  }
}

Future<Option<Principal>> testLookup(String username, String password) {
  final validUser = username == 'Aladdin' && password == 'open sesame';

  final principalOpt =
      validUser ? new Some(new Principal(username)) : const None();

  return new Future.value(principalOpt);
}
