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


/**
 * This example has a login route where username and password are POSTed
 * and other routes which are autheticated via the JWT session established
 * via the login route
 */
void main() {

  Logger.root.level = Level.FINER;
  Logger.root.onRecord.listen((lr) {
    print('${lr.time} ${lr.level} ${lr.message}');
  });

  var testLookup = new TestUserLookup();

  // use Jwt based sessions. Create the secret using a UUID
  var sessionHandler = new JwtSessionHandler('super app', new Uuid().v4(),
        testLookup.lookupByUsername);

  // allow http for testing with curl. Don't use in production
  var allowHttp = true;

  // authentication middleware for a login handler (e.g. submitted from a form)
  var loginMiddleware = authenticate(
      [new UsernamePasswordAuthenticator(testLookup.lookupByUsernamePassword)],
      sessionHandler: sessionHandler, allowHttp: allowHttp,
      allowAnonymousAccess: false);

  // authentication middleware for routes other than login that require a logged
  // in user. Here we are relying
  // solely on users with a session established via the /login route but
  // could have additional authenitcators here.
  // We are disabling anonymous access to these routes
  var defaultAuthMiddleware = authenticate([],
      sessionHandler: sessionHandler, allowHttp: true,
      allowAnonymousAccess: false);

  var rootRouter = router(handlerAdapter: handlerAdapter());

  // the route where the login form credentials are posted
  rootRouter.post('/login', (Request request) => new Response.ok(
          "I'm now logged in as ${loggedInUsername(request)}\n"),
            middleware: loginMiddleware);

  // the routes which require an authenticated user
  rootRouter.child('/authenticated', middleware: defaultAuthMiddleware)
    ..get('/foo', (Request request) => new Response.ok(
        "Doing foo as ${loggedInUsername(request)}\n"));

  printRoutes(rootRouter);

  var handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(exceptionResponse())
      .addHandler(rootRouter.handler);

  io.serve(handler, 'localhost', 8080).then((server) {
    print('Serving at http://${server.address.host}:${server.port}');
  });
}

String loggedInUsername(Request request) =>
    getAuthenticationContext(request).map((ac) => ac.principal.name)
              .getOrElse(() => 'guest');


class TestUserLookup {
  Future<Option<Principal>> lookupByUsernamePassword(String username, String password) {
    final validUser = username == 'fred';

    final principalOpt = validUser ? new Some(new Principal(username)) :
      const None();

    return new Future.value(principalOpt);
  }

  Future<Option<Principal>> lookupByUsername(String username) {
    final validUser = username == 'fred';

    final principalOpt = validUser ? new Some(new Principal(username)) :
      const None();

    return new Future.value(principalOpt);
  }
}