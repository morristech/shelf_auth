library shelf_auth.test;

import 'package:shelf_auth/shelf_auth.dart';

import 'package:unittest/unittest.dart';
import 'package:mock/mock.dart';
import 'package:option/option.dart';
import 'package:shelf/shelf.dart';
import 'dart:async';

class MockAuthenticator extends Mock implements Authenticator {
  noSuchMethod(_) => super.noSuchMethod(_);
}

//typedef Handler(Request request);
abstract class HandlerClass {
  dynamic call(Request request) { return null; }
}

class MockHandler extends Mock implements HandlerClass {
  noSuchMethod(_) => super.noSuchMethod(_);
}


main() {
  MockAuthenticator authenticator1;
  MockAuthenticator authenticator2;
  MockAuthenticator authenticator3;
  MockHandler handler;

  final request = new Request('GET', Uri.parse('http://blah/foo'));

  setUp(() {
    authenticator1 = new MockAuthenticator();
    authenticator2 = new MockAuthenticator();
    authenticator3 = new MockAuthenticator();
    handler = new MockHandler();
  });

  group('authenticationMiddleware', () {
    group('when passed an empty list of authenticators', () {
      final mw = authenticationMiddleware([]);
      final middlewareHandler = mw(handler);

      test('completes', () {
        expect(middlewareHandler(request), completes);
      });

      test("doesn't call handler", () {
        final f = middlewareHandler(request);
        f.then((response) {
          handler.calls('call').verify(neverHappened);
        });
        expect(f, completes);

      });

      test('returns 401 response', () {
        expect(middlewareHandler(request), completion(responseWithStatus(401)));
      });
    });

    group('when all authenticators return None', () {
      var middlewareHandler;
      setUp(() {
        authenticator1.when(callsTo('authenticate'))
          .alwaysReturn(new Future.value(const None()));
        authenticator2.when(callsTo('authenticate'))
          .alwaysReturn(new Future.value(const None()));
        final mw = authenticationMiddleware([authenticator1, authenticator2]);
        middlewareHandler = mw(handler);
      });


      test('completes', () {
        expect(middlewareHandler(request), completes);
      });

      test("doesn't call handler", () {
        final f = middlewareHandler(request);
        f.then((response) {
          handler.calls('call').verify(neverHappened);
        });
        expect(f, completes);

      });

      test("calls all authenticators", () {
        final f = middlewareHandler(request);
        f.then((response) {
          authenticator1.calls('authenticate').verify(happenedOnce);
          authenticator2.calls('authenticate').verify(happenedOnce);
        });
        expect(f, completes);

      });

      test('returns 401 response', () {
        expect(middlewareHandler(request), completion(responseWithStatus(401)));
      });
    });
  });
}



Matcher responseWithStatus(matcher) => responseMatcher("statusCode", matcher,
    (Response r) => r.statusCode);

Matcher responseMatcher(String fieldName, matcher, Getter getter)
    => fieldMatcher("Response", fieldName, matcher, getter);

Matcher fieldMatcher(String className, String fieldName, matcher,
                     Getter getter) =>
    new FieldMatcher(className, fieldName, matcher, getter);


typedef Getter(object);

class FieldMatcher extends CustomMatcher {
  final Getter getter;

  FieldMatcher(String className, String fieldName, matcher, this.getter)
      : super("$className with $fieldName that", fieldName, matcher);

  featureValueOf(actual) => getter(actual);
}
