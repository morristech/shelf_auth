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
import 'package:uuid/uuid.dart';

void main() {

  var authMiddleware = authenticate([new RandomAuthenticator()],
      new JwtSessionHandler('super app', new Uuid().v4(), testLookup));

  var handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(exceptionResponse())
      .addMiddleware(authMiddleware)
      .addHandler((Request request) => new Response.ok("I'm in with "
          "${getAuthenticationContext(request).map((ac) => ac.principal.name)}\n"));

  io.serve(handler, 'localhost', 8080).then((server) {
    print('Serving at http://${server.address.host}:${server.port}');
  });
}

class RandomAuthenticator extends Authenticator {
  bool approve = true;

  @override
  Future<Option<AuthenticationContext>> authenticate(Request request) {
    approve = !approve;

    return new Future.value(approve ?
        new Some(new AuthenticationContext(new Principal("fred")))
        : throw new UnauthorizedException());
  }
}

Future<Option<Principal>> testLookup(String username) {
  final validUser = username == 'fred';

  final principalOpt = validUser ? new Some(new Principal(username)) :
    const None();

  return new Future.value(principalOpt);
}
