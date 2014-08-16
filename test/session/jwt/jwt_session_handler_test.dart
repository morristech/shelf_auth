// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.session.jwt.handler.test;

import 'package:shelf_auth/src/session/jwt/jwt_session.dart';
import 'package:shelf_auth/src/session/jwt/jwt_session_handler.dart';
import 'package:unittest/unittest.dart';
import 'package:shelf_auth/src/principal/user_lookup.dart';
import 'dart:async';
import 'package:shelf_auth/shelf_auth.dart';
import 'package:option/option.dart';
import 'package:shelf/shelf.dart';
import 'dart:io';

const String secret = 'sshhh  its a secret';
const String issuer = 'da issuer';
const String subject = 'el subjecto';

final UserLookupByUsername lookup = testLookup;

main() {

  JwtSessionHandler sessionHandler() => new JwtSessionHandler(
      issuer, secret, lookup);

  DateTime sessionFirstCreated = new DateTime.now().subtract(const Duration(hours: 10));
  DateTime sessionLastRefreshed = new DateTime.now();
  DateTime expiredNoSessionRenewalAfter = new DateTime.now().subtract(
      const Duration(seconds: 1));

  DateTime activeNoSessionRenewalAfter = new DateTime.now().add(
      const Duration(seconds: 10));

  AuthenticatedContext context(bool expired) => new SessionAuthenticatedContext(
      new Principal('fred'), sessionFirstCreated, sessionLastRefreshed,
      expired ? expiredNoSessionRenewalAfter : activeNoSessionRenewalAfter);

  request() => new Request('GET', Uri.parse('http://localhost/foo'));
  requestWithHeader(Map headers) =>
      new Request('GET', Uri.parse('http://localhost/foo'), headers: headers);
  response() => new Response.ok('foo');



  group('handle', () {

    group('does not change response', () {
      group('when total session timeout expired', () {
        final resp = response();
        test('', () {
          expect(sessionHandler().handle(context(true), request(), resp),
              same(resp));
        });
      });
    });
    group('adds authorization header when session valid', () {
      Response handle(Response resp) =>
          sessionHandler().handle(context(false), request(), resp);


      test('and changes response', () {
        final resp = response();
        expect(handle(resp), isNot(same(resp)));
      });

      test('and adds a header', () {
        expect(handle(response()).headers, hasLength(1));
      });

      test('and adds an authorization header', () {
        expect(handle(response()).headers[HttpHeaders.AUTHORIZATION],
            isNotNull);
      });

      test('and adds an authorization header with correct auth scheme', () {
        expect(handle(response()).headers[HttpHeaders.AUTHORIZATION],
            startsWith(JWT_SESSION_AUTH_SCHEME));
      });

      test('and adds an authorization header which would validate successfully', () {
        final authheader = handle(response()).headers[HttpHeaders.AUTHORIZATION];
        final req = requestWithHeader({ HttpHeaders.AUTHORIZATION: authheader });

        expect(sessionHandler().authenticator.authenticate(req), completes);
        expect(sessionHandler().authenticator.authenticate(req),
            completion(new isInstanceOf<Some>()));
      });
    });
  });

}


Future<Option<Principal>> testLookup(String username) {
  return new Future.value(new Some(new Principal(username)));
}
