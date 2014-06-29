library shelf_auth.test;

import 'package:shelf_auth/shelf_auth.dart';

import 'package:unittest/unittest.dart';
import 'package:mock/mock.dart';
import 'package:option/option.dart';
import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:shelf_exception_response/exception.dart';
import 'src/matchers.dart';

// TODO: avoid the dupe
const String _SHELF_AUTH_REQUEST_CONTEXT = 'shelf.auth.context';


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

class MockSessionHandler extends Mock implements SessionHandler {
  noSuchMethod(_) => super.noSuchMethod(_);
}


main() {
  MockAuthenticator authenticator1;
  MockAuthenticator authenticator2;
  MockAuthenticator authenticator3;
  MockHandler handler;

  final request = new Request('GET', Uri.parse('http://blah/foo'));
  final okResponse = new Response.ok('sweet');
  final defaultAuthContext = new AuthenticationContext(new Principal("fred"));

  setUp(() {
    authenticator1 = new MockAuthenticator();
    authenticator2 = new MockAuthenticator();
    authenticator3 = new MockAuthenticator();
    handler = new MockHandler();
    handler.when(callsTo('call')).alwaysReturn(okResponse);
  });

  group('authenticationMiddleware', () {
    group('when passed an empty list of authenticators', () {
      var middlewareHandler;
      setUp(() {
        final mw = authenticate([]);
        middlewareHandler = mw(handler);
      });

      test('completes', () {
        expect(middlewareHandler(request), completes);
      });

      test("calls handler with no auth context in request", () {
        final f = middlewareHandler(request);
        f.then((response) {
          handler.calls('call').verify(happenedOnce);
          handler.calls('call', requestWithContextValue(
                _SHELF_AUTH_REQUEST_CONTEXT, isNull))
              .verify(happenedOnce);
        });
        expect(f, completes);
      });

      test('returns 200 response', () {
        expect(middlewareHandler(request), completion(responseWithStatus(200)));
      });
    });

    group('when all authenticators return None', () {
      var middlewareHandler;
      setUp(() {
        authenticator1.when(callsTo('authenticate'))
          .alwaysReturn(new Future.value(const None()));
        authenticator2.when(callsTo('authenticate'))
          .alwaysReturn(new Future.value(const None()));
        final mw = authenticate([authenticator1, authenticator2]);
        middlewareHandler = mw(handler);
      });


      test('completes', () {
        expect(middlewareHandler(request), completes);
      });

      test("calls handler with no auth context in request", () {
        final f = middlewareHandler(request);
        f.then((response) {
          handler.calls('call').verify(happenedOnce);
          handler.calls('call', requestWithContextValue(
                _SHELF_AUTH_REQUEST_CONTEXT, isNull))
              .verify(happenedOnce);
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

      test('returns 200 response', () {
        expect(middlewareHandler(request), completion(responseWithStatus(200)));
      });
    });

    group('when first authenticator throws UnauthorizedException', () {
      var middlewareHandler;
      setUp(() {
        authenticator1.when(callsTo('authenticate'))
          .alwaysReturn(new Future.error(new UnauthorizedException()));
        authenticator2.when(callsTo('authenticate'))
          .alwaysReturn(new Future.value(const None()));
        final mw = authenticate([authenticator1, authenticator2]);
        middlewareHandler = mw(handler);
      });


      test('completes', () {
        expect(middlewareHandler(request), throws);
      });

      test("doesn't call handler", () {
        final Future f = middlewareHandler(request);
        f.whenComplete(() {
          handler.calls('call').verify(neverHappened);
        });
        expect(f, throws);

      });

      test("doesn't call remaining authenticators", () {
        final f = middlewareHandler(request);
        f.then((response) {
          authenticator1.calls('authenticate').verify(happenedOnce);
          authenticator2.calls('authenticate').verify(neverHappened);
        });
        expect(f, throws);

      });

    });

    group('when middle authenticator returns Some', () {
      var middlewareHandler;
      setUp(() {
        authenticator1.when(callsTo('authenticate'))
          .alwaysReturn(new Future.value(const None()));
        authenticator2.when(callsTo('authenticate'))
          .alwaysReturn(new Future.value(
              new Some(defaultAuthContext)));
        authenticator3.when(callsTo('authenticate'))
          .alwaysReturn(new Future.value(const None()));

        final mw = authenticate([authenticator1, authenticator2,
                                             authenticator3]);
        middlewareHandler = mw(handler);
      });


      test('completes', () {
        expect(middlewareHandler(request), completes);
      });

      test("calls handler with auth context in request", () {
        final f = middlewareHandler(request);
        f.then((response) {
          handler.calls('call').verify(happenedOnce);

          handler.calls('call', requestWithContextValue(
              _SHELF_AUTH_REQUEST_CONTEXT, isNotNull)).verify(happenedOnce);

          handler.calls('call', requestWithContextValue(
              _SHELF_AUTH_REQUEST_CONTEXT, equals(defaultAuthContext)))
              .verify(happenedOnce);
        });
        expect(f, completes);
      });

      test("calls first 2 authenticators but not last", () {
        final f = middlewareHandler(request);
        f.then((response) {
          authenticator1.calls('authenticate').verify(happenedOnce);
          authenticator2.calls('authenticate').verify(happenedOnce);
          authenticator3.calls('authenticate').verify(neverHappened);
        });
        expect(f, completes);

      });

      test('returns 200 response', () {
        expect(middlewareHandler(request), completion(responseWithStatus(200)));
      });
    });

    group('does not call sessionHandler when auth fails', () {
      MockSessionHandler sessionHandler;

      setUp(() {
        sessionHandler = new MockSessionHandler();
        sessionHandler.when(callsTo('handle')).alwaysCall(okResponse);
      });

      Handler authHandler(Iterable<Authenticator> auths) {
        final mw = authenticate(auths, sessionHandler);
        return mw(handler);
      }

      verifyHandlerNotCalledFor(Iterable<Authenticator> auths) {
        final f = authHandler(auths)(request);
        f.then((response) {
          sessionHandler.calls('handle').verify(neverHappened);
        });
        expect(f, completes);
      }

      test("for empty authenticators", () {
        verifyHandlerNotCalledFor([]);
      });

      test("for non matching authenticators", () {
        authenticator1.when(callsTo('authenticate'))
          .alwaysReturn(new Future.value(const None()));

        verifyHandlerNotCalledFor([authenticator1]);
      });

      test("for invalid auth", () {
        authenticator1.when(callsTo('authenticate'))
          .alwaysReturn(new Future.error(new UnauthorizedException()));

        verifyHandlerNotCalledFor([authenticator1]);
      });
    });

    group('calls sessionHandler when auth succeeds', () {
      MockSessionHandler sessionHandler;
      var authHandler;

      setUp(() {
        sessionHandler = new MockSessionHandler();
        sessionHandler.when(callsTo('handle')).alwaysReturn(okResponse);

        authenticator1.when(callsTo('authenticate'))
          .alwaysReturn(new Future.value(new Some(defaultAuthContext)));

        final mw = authenticate([authenticator1], sessionHandler);
        authHandler = mw(handler);

      });


      verifyHandlerCalledFor(sessionHandlerCalls(MockSessionHandler sessionHandler)) {
        final f = authHandler(request);
        f.then((response) {
          sessionHandlerCalls(sessionHandler).verify(happenedOnce);
        });
        expect(f, completes);
      }

      test("", () {
        verifyHandlerCalledFor((sh) => sh.calls('handle'));
      });

      test("with correct auth context", () {
        verifyHandlerCalledFor((sh) => sh.calls('handle', defaultAuthContext));
      });

      test("with correct request", () {
        verifyHandlerCalledFor((sh) => sh.calls('handle', anything, request));
      });

      test("with correct response", () {
        verifyHandlerCalledFor((sh) => sh.calls('handle', anything, anything,
            okResponse));
      });
    });

    group('does not call sessionHandler when session creation and update not allowed', () {
      MockSessionHandler sessionHandler;
      final authContext = new AuthenticationContext(new Principal("fred"),
          sessionCreationAllowed: false, sessionUpdateAllowed: false);
      var authHandler;

      setUp(() {
        sessionHandler = new MockSessionHandler();
        sessionHandler.when(callsTo('handle')).alwaysReturn(okResponse);

        authenticator1.when(callsTo('authenticate'))
          .alwaysReturn(new Future.value(new Some(authContext)));

        final mw = authenticate([authenticator1], sessionHandler);
        authHandler = mw(handler);
      });

      test("", () {
        final f = authHandler(request);
        f.then((response) {
          sessionHandler.calls('handle').verify(neverHappened);
        });
        expect(f, completes);
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
