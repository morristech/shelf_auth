library shelf_auth.authentication.basic.test;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:crypto/crypto.dart';
import 'package:shelf_auth/src/authentication.dart';
import 'package:shelf_auth/src/authenticators/basic_auth.dart';
import 'package:unittest/unittest.dart';

//


final UserLookupByUsernamePassword lookup = new TestLookup();

main() {
  request() => new Request('GET', Uri.parse('http://localhost/foo'),
    headers: { 'Authorization': 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==' });

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
          expect(authenticator.authenticate(request()),
            completion((optContext) => optContext.get().principal.name == 'Aladdin'));
        });
      });

    });



  });

}

class TestLookup extends UserLookupByUsernamePassword<Principal> {

  @override
  Future<Option<Principal>> lookup(String username, String password) {
    final validUser = username == 'Aladdin' && password == 'open sesame';

    final principalOpt = validUser ? new Some(new Principal(username)) :
      const None();

    return new Future.value(principalOpt);
  }
}