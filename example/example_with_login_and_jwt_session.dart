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
import 'package:logging/logging.dart';
import 'package:shelf_route/shelf_route.dart';
import 'package:shelf_bind/shelf_bind.dart';
import 'package:shelf_auth/src/authenticators/username_password_auth.dart';

////typedef Handler Middleware(Handler innerHandler);
//typedef BindMiddleware(Handler innerHandler);
//
//jsonLoginMiddleware(Handler innerHandler) {
//  return (@RequestBody(format: ContentType.JSON)
//      LoginCredentials credentials, Request request) {
//    final newRequest =
//        request.change(context: { 'shelf_auth.credentials': credentials });
//    return syncFuture(innerHandler(newRequest));
//  };
//}
//
//class LoginCredentials {
//  String username;
//  String password;
//
//  LoginCredentials.fromJson(Map json)
//      : username = json['username'],
//        password = json['password'];
//}

final SessionHandler sessionHandler =
  new JwtSessionHandler('super app', new Uuid().v4(), testLookup);


//// TODO: shelf bind to support inferring content type from headers
//usernamePasswordBodyParser(@RequestBody(format: ContentType.JSON)
//             LoginCredentials creds, Request request) {
//  final UsernamePasswordAuthenticator authenticator =
//    new UsernamePasswordAuthenticator(testUPLookup, (_) => creds.username,
//      (_) => creds.password);
//
//  return authenticator.authenticate(request).then((contextOpt) {
//    return contextOpt.map((context) {
//      return sessionHandler.handle(context, request,
//          new Response.ok("logged in"));
//    }).orElse(() => throw new UnauthorizedException());
//  });
//}

void main() {

  Logger.root.level = Level.FINER;
  Logger.root.onRecord.listen((lr) {
    print('${lr.time} ${lr.level} ${lr.message}');
  });

  // TODO: as this has a session handler it will ignore any new login credentials
  // in this request. i.e. the session auth will win
  // That may be ok. The user must log out first
  var loginMiddleware = authenticate(
      [new UsernamePasswordAuthenticator(testUPLookup)],
//      usernamePasswordBodyParser: usernamePasswordBodyParser,
      sessionHandler: sessionHandler,
          // allow http for testing with curl. Don't do in production
          allowHttp: true);

  var rootRouter = router(handlerAdapter: handlerAdapter())
      ..post('/login', (Request request) => new Response.ok("I'm now logged in as "
          "${getAuthenticationContext(request).map((ac) => ac.principal.name)
            .getOrElse(() => 'guest')}\n"),
            middleware: loginMiddleware);

  var authMiddleware = authenticate([],
      sessionHandler: sessionHandler,
          // allow http for testing with curl. Don't do in production
          allowHttp: true);

  rootRouter.child('/authenticated', middleware: authMiddleware)
    ..get('/foo', (Request request) => new Response.ok("I'm in as "
        "${getAuthenticationContext(request).map((ac) => ac.principal.name)
          .getOrElse(() => 'guest')}\n"));

  printRoutes(rootRouter);

  var handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(exceptionResponse())
      .addHandler(rootRouter.handler);

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

Future<Option<Principal>> testUPLookup(String username, String password) {
  final validUser = username == 'fred';

  final principalOpt = validUser ? new Some(new Principal(username)) :
    const None();

  return new Future.value(principalOpt);
}

Future<Option<Principal>> testLookup(String username) {
  final validUser = username == 'fred';

  final principalOpt = validUser ? new Some(new Principal(username)) :
    const None();

  return new Future.value(principalOpt);
}
