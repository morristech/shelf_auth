library shelf_auth.authentication.session.jwt.test;

import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:shelf_auth/src/authentication.dart';
import 'package:unittest/unittest.dart';
import 'package:shelf_auth/src/principal/user_lookup.dart';
import 'package:shelf_auth/src/session/jwt/jwt_session_auth.dart';
import 'package:shelf_auth/src/session/jwt/jwt_session.dart';
import 'package:dart_jwt/dart_jwt.dart';


final UserLookupByUsername lookup = testLookup;
const String secret = 'sshhh  its a secret';
const String issuer = 'da issuer';
const String subject = 'el subjecto';

main() {
  final String sessionToken = createSessionToken(secret, issuer, subject);
  final String expiredToken = createExpiredSessionToken(secret, issuer, subject);
  
  request() => new Request('GET', Uri.parse('http://localhost/foo'),
    headers: { 'Authorization': '$JWT_SESSION_AUTH_SCHEME $sessionToken' });

  requestExpired() => new Request('GET', Uri.parse('http://localhost/foo'),
    headers: { 'Authorization': '$JWT_SESSION_AUTH_SCHEME $expiredToken' });

  requestInvalidCredentials() => new Request('GET', Uri.parse('http://localhost/foo'),
    headers: { 'Authorization': '$JWT_SESSION_AUTH_SCHEME QWxhZGRpbjpvcGVuIHNlc2FtZQXXXXXX==' });

  requestWrongRealm() => new Request('GET', Uri.parse('http://localhost/foo'),
    headers: { 'Authorization': 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==' });

  requestNoAuth() => new Request('GET', Uri.parse('http://localhost/foo'),
    headers: { 'Foo': 'bar' });

  final authenticator = new JwtSessionAuthenticator(lookup, secret);

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
            completion((optContext) => optContext.get().principal.name == subject));
        });
      });

      group('and credentials is for invalid user', () {
        test('throws', () {
          expect(() => authenticator.authenticate(requestInvalidCredentials()), throws);
        });
      });
      
      group('and session expired', () {
        test('throws', () {
          expect(() => authenticator.authenticate(requestExpired()), throws);
        });
      });


      group('and Realm is not $JWT_SESSION_AUTH_SCHEME', () {
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

Future<Option<Principal>> testLookup(String username) {
  final validUser = username == subject;

  final principalOpt = validUser ? new Some(new Principal(username)) :
    const None();

  return new Future.value(principalOpt);
}


String createExpiredSessionToken(String secret, String issuer, String subject,
    { Duration idleTimeout: const Duration(minutes: 30),
      Duration totalSessionTimeout: const Duration(days: 1),
      String audience }) {

  final iat = new DateTime.now().subtract(const Duration(days:2));

  final claimSet = new SessionClaimSet(issuer, subject,
    iat.add(idleTimeout), iat, audience, iat.add(totalSessionTimeout));

  final jwt = new JsonWebToken.jws(claimSet, new JwaSignatureContext(secret));
  return jwt.encode();
}
