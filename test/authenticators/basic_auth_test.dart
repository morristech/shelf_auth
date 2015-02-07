// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authentication.basic.test;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:shelf_auth/src/authentication.dart';
import 'package:shelf_auth/src/authenticators/basic_auth.dart';
import 'package:unittest/unittest.dart';
import 'package:shelf_auth/src/principal/user_lookup.dart';

final UserLookupByUsernamePassword lookup = testLookup;

main() {
  request() => new Request('GET', Uri.parse('http://localhost/foo'),
      headers: {'Authorization': 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='});

  requestInvalidCredentials() => new Request(
      'GET', Uri.parse('http://localhost/foo'),
      headers: {'Authorization': 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQXXXXXX=='});

  requestWrongRealm() => new Request('GET', Uri.parse('http://localhost/foo'),
      headers: {'Authorization': 'Complex QWxhZGRpbjpvcGVuIHNlc2FtZQ=='});

  requestNoAuth() => new Request('GET', Uri.parse('http://localhost/foo'),
      headers: {'Foo': 'bar'});

  final authenticator = new BasicAuthenticator(lookup);

  group('authenticate', () {
    group('when Authorization header is present', () {
      group('and credentials is for valid user', () {
        test('completes', () {
          expect(authenticator.authenticate(request()), completes);
        });

        test('completes with Some', () {
          expect(authenticator.authenticate(request()),
              completion(new isInstanceOf<Some>()));
        });

        test('completes with a principal', () {
          expect(authenticator.authenticate(request()),
              completion((optContext) => optContext.get().principal != null));
        });

        test('completes with correct principal', () {
          expect(authenticator.authenticate(request()), completion(
              (optContext) => optContext.get().principal.name == 'Aladdin'));
        });
      });

      group('and credentials is for invalid user', () {
        test('throws', () {
          expect(() => authenticator.authenticate(requestInvalidCredentials()),
              throws);
        });

//        test('completes with None', () {
//          expect(authenticator.authenticate(requestInvalidCredentials()),
//          completion(new isInstanceOf<None>()));
//        });
      });

      group('and Realm is not Basic', () {
        test('completes', () {
          expect(authenticator.authenticate(requestWrongRealm()), completes);
        });

        test('completes with None', () {
          expect(authenticator.authenticate(requestWrongRealm()),
              completion(new isInstanceOf<None>()));
        });
      });
    });

    group('when no Authorization header is present', () {
      test('completes', () {
        expect(authenticator.authenticate(requestNoAuth()), completes);
      });

      test('completes with None', () {
        expect(authenticator.authenticate(requestNoAuth()),
            completion(new isInstanceOf<None>()));
      });
    });
  });
}

Future<Option<Principal>> testLookup(String username, String password) {
  final validUser = username == 'Aladdin' && password == 'open sesame';

  final principalOpt =
      validUser ? new Some(new Principal(username)) : const None();

  return new Future.value(principalOpt);
}
