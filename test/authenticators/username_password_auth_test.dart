library shelf_auth.authentication.usernamepassword.test;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:shelf_auth/src/authentication.dart';
import 'package:shelf_auth/src/authenticators/username_password_auth.dart';
import 'package:unittest/unittest.dart';
import 'package:shelf_auth/src/principal/user_lookup.dart';


final UserLookupByUsernamePassword lookup = testLookup;

main() {
  request() => new Request('POST', Uri.parse('http://localhost/login'),
    headers: { 'Content-type': "application/x-www-form-urlencoded" },
    body: new Stream.fromIterable(["username=Aladdin&password=opensesame".codeUnits]));

  requestInvalidCredentials() => new Request('POST',
      Uri.parse('http://localhost/login'),
      headers: { 'Content-type': "application/x-www-form-urlencoded" },
      body: new Stream.fromIterable(["username=Aladdin&password=foo".codeUnits]));

  requestNoAuth() => new Request('POST', Uri.parse('http://localhost/login'),
    headers: { 'Foo': 'bar' });

  final authenticator = new UsernamePasswordAuthenticator(lookup);

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
          expect(authenticator.authenticate(request()),
            completion((optContext) => optContext.get().principal.name == 'Aladdin'));
        });
      });

      group('and credentials is for invalid user', () {
        test('throws', () {
          expect(authenticator.authenticate(requestInvalidCredentials()), throws);
        });
      });

    });

    group('when no Authorization header is present', () {
      test('throws', () {
        expect(authenticator.authenticate(requestNoAuth()), throws);
      });

      // This is different to normal authenticators as it is used in routes
      // that are dedicated to login so we throw when no credentials rather
      // that returning None.

//      test('completes', () {
//        expect(authenticator.authenticate(requestNoAuth()), completes);
//      });
//
//      test('completes with None', () {
//        expect(authenticator.authenticate(requestNoAuth()),
//        completion(new isInstanceOf<None>()));
//      });


    });


  });

}

Future<Option<Principal>> testLookup(String username, String password) {
  final validUser = username == 'Aladdin' && password == 'opensesame';

  final principalOpt = validUser ? new Some(new Principal(username)) :
    const None();

  return new Future.value(principalOpt);
}
