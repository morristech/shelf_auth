// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.test;

import 'dart:async';

import 'package:http_exception/http_exception.dart';
import 'package:mockito/mockito.dart';
import 'package:option/option.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_auth/shelf_auth.dart';
import 'package:shelf_auth/src/authentication_impl.dart';
import 'package:test/test.dart';

import 'src/matchers.dart';

class MockAuthenticator extends Mock implements Authenticator {}

//typedef Handler(Request request);
abstract class HandlerClass {
  dynamic call(Request request) {
    return null;
  }
}

class MockHandler extends Mock implements HandlerClass {}

class MockSessionHandler extends Mock implements SessionHandler {}

main() {
  MockAuthenticator authenticator1;
  MockAuthenticator authenticator2;
  MockAuthenticator authenticator3;
  MockAuthenticator sessionAuthenticator;
  MockHandler handler;
  Option<AuthenticatedContext> contextInZoneDuringHandler;

  Request request() => new Request('GET', Uri.parse('https://blah/foo'));
  Request httpRequest() => new Request('GET', Uri.parse('http://blah/foo'));
  final okResponse = new Response.ok('sweet');
  final defaultAuthContext = new AuthenticatedContext(new Principal("fred"));

  setUp(() {
    authenticator1 = new MockAuthenticator();
    authenticator2 = new MockAuthenticator();
    authenticator3 = new MockAuthenticator();
    sessionAuthenticator = new MockAuthenticator();
    handler = new MockHandler();
    contextInZoneDuringHandler = const None();
    when(handler.call(argThat(new isInstanceOf<Request>())))
        .thenAnswer((invocation) {
      contextInZoneDuringHandler = authenticatedContext();
      return okResponse;
    });
    when(authenticator1.readsBody).thenReturn(false);
    when(authenticator2.readsBody).thenReturn(false);
    when(authenticator3.readsBody).thenReturn(false);
    when(sessionAuthenticator.readsBody).thenReturn(false);
  });

  group('authenticationMiddleware', () {
    group('when passed an empty list of authenticators', () {
      var middlewareHandler;
      setUp(() {
        final mw = authenticate([]);
        middlewareHandler = mw((Request r) => handler.call(r));
      });

      test('completes', () {
        expect(middlewareHandler(request()), completes);
      });

      group('on completion', () {
        var response;
        setUp(() {
          final f = middlewareHandler(request());
          return f.then((resp) {
            response = resp;
          });
        });

        test("calls handler with no auth context in request", () {
          verify(handler.call(argThat(
                  requestWithContextValue(SHELF_AUTH_REQUEST_CONTEXT, isNull))))
              .called(1);
        });

        test("calls handler with no auth context in zone", () {
          expect(contextInZoneDuringHandler, new isInstanceOf<None>());
        });

        test('returns 200 response', () {
          expect(response, responseWithStatus(200));
        });
      });
    });

    group('when all authenticators return None', () {
      var middlewareHandler;
      setUp(() {
        when(authenticator1.authenticate(any))
            .thenReturn(new Future.value(const None()));
        when(authenticator2.authenticate(any))
            .thenReturn(new Future.value(const None()));
        final mw = authenticate([authenticator1, authenticator2]);
        middlewareHandler = mw((Request r) => handler.call(r));
      });

      test('completes', () {
        expect(middlewareHandler(request()), completes);
      });

      group('on completion', () {
        var response;
        setUp(() {
          final f = middlewareHandler(request());
          return f.then((resp) {
            response = resp;
          });
        });

        test("calls handler with no auth context in request", () {
          verify(handler.call(argThat(
                  requestWithContextValue(SHELF_AUTH_REQUEST_CONTEXT, isNull))))
              .called(1);
        });

        test("calls handler with no auth context in zone", () {
          expect(contextInZoneDuringHandler, new isInstanceOf<None>());
        });

        test("calls all authenticators", () {
          verify(authenticator1.authenticate(any)).called(1);
          verify(authenticator2.authenticate(any)).called(1);
        });

        test('returns 200 response', () {
          expect(response, responseWithStatus(200));
        });
      });
    });

    group(
        'when allowAnonymousAccess is false and all authenticators return None',
        () {
      var middlewareHandler;
      setUp(() {
        when(authenticator1.authenticate(any))
            .thenReturn(new Future.value(const None()));
        when(authenticator2.authenticate(any))
            .thenReturn(new Future.value(const None()));
        final mw = authenticate([authenticator1, authenticator2],
            allowAnonymousAccess: false);
        middlewareHandler = mw((Request r) => handler.call(r));
      });

      test('completes', () {
        expect(middlewareHandler(request()),
            throwsA(new isInstanceOf<UnauthorizedException>()));
      });
    });

    group('when first authenticator throws UnauthorizedException', () {
      var middlewareHandler;
      setUp(() {
        when(authenticator1.authenticate(any))
            .thenAnswer((_) => new Future.error(new UnauthorizedException()));
        when(authenticator2.authenticate(any))
            .thenReturn(new Future.value(const None()));
        final mw = authenticate([authenticator1, authenticator2]);
        middlewareHandler = mw((Request r) => handler.call(r));
      });

      test('completes', () {
        expect(middlewareHandler(request()), throws);
      });

      test("doesn't call handler", () {
        final Future f = middlewareHandler(request());
        f.then((_) {
          fail('show throw');
        }, onError: (_) {
          verifyNever(handler.call(any));
        });
        expect(f, throws);
      });

      test("doesn't call remaining authenticators", () {
        final f = middlewareHandler(request());
        f.then((_) {
          fail('show throw');
        }, onError: (_) {
          verify(authenticator1.authenticate(any)).called(1);
          verifyNever(authenticator2.authenticate(any));
        });
        expect(f, throws);
      });
    });

    group('when middle authenticator returns Some', () {
      var middlewareHandler;
      setUp(() {
        when(authenticator1.authenticate(any))
            .thenReturn(new Future.value(const None()));
        when(authenticator2.authenticate(any))
            .thenReturn(new Future.value(new Some(defaultAuthContext)));
        when(authenticator3.authenticate(any))
            .thenReturn(new Future.value(const None()));

        final mw =
            authenticate([authenticator1, authenticator2, authenticator3]);
        middlewareHandler = mw((Request r) => handler.call(r));
      });

      test('completes', () {
        expect(middlewareHandler(request()), completes);
      });

      group('on completion', () {
        var response;
        setUp(() {
          final f = middlewareHandler(request());
          return f.then((resp) {
            response = resp;
          });
        });

        test("calls handler with auth context in request", () {
          verify(handler.call(argThat(requestWithContextValue(
                  SHELF_AUTH_REQUEST_CONTEXT, equals(defaultAuthContext)))))
              .called(1);
        });

        test("calls handler with auth context in zone", () {
          expect(contextInZoneDuringHandler, new isInstanceOf<Some>());
          expect(contextInZoneDuringHandler.get(), equals(defaultAuthContext));
        });

        test("calls first 2 authenticators but not last", () {
          verify(authenticator1.authenticate(any)).called(1);
          verify(authenticator2.authenticate(any)).called(1);
          verifyNever(authenticator3.authenticate(any));
        });

        test('returns 200 response', () {
          expect(response, responseWithStatus(200));
        });
      });
    });

    group('when request over http and authenticator returns Some', () {
      setUp(() {
        when(authenticator1.authenticate(any))
            .thenReturn(new Future.value(new Some(defaultAuthContext)));
      });

      middlewareHandler(bool allowHttp) {
        final mw = authenticate([authenticator1], allowHttp: allowHttp);
        return mw((Request r) => handler.call(r));
      }

      test('and allowHttp false then UnauthorizedException thrown', () {
        expect(middlewareHandler(false)(httpRequest()),
            throwsA(new isInstanceOf<UnauthorizedException>()));
      });

      test('and allowHttp true then returns response', () {
        expect(middlewareHandler(true)(httpRequest()),
            completion(new isInstanceOf<Response>()));
      });
    });

    group('does not call sessionHandler when auth fails', () {
      MockSessionHandler sessionHandler;

      setUp(() {
        sessionHandler = new MockSessionHandler();
        when(sessionHandler.handle(any, any, any)).thenReturn(okResponse);
      });

      Handler authHandler(Iterable<Authenticator> auths) {
        final mw = authenticate(auths, sessionHandler: sessionHandler);
        return mw((Request r) => handler.call(r));
      }

      verifyHandlerNotCalledFor(Iterable<Authenticator> auths) {
        final f = authHandler(auths)(request());
        f.then((response) {
          verifyNever(sessionHandler.handle(any, any, any));
        }, onError: (_) {
          verifyNever(sessionHandler.handle(any, any, any));
        });
      }

      test("for empty authenticators", () {
        verifyHandlerNotCalledFor([]);
      });

      test("for non matching authenticators", () {
        when(authenticator1.authenticate(any))
            .thenReturn(new Future.value(const None()));

        verifyHandlerNotCalledFor([authenticator1]);
      });

      test("for invalid auth", () {
        when(authenticator1.authenticate(any))
            .thenAnswer((_) => new Future.error(new UnauthorizedException()));

        verifyHandlerNotCalledFor([authenticator1]);
      });
    });

    group('calls sessionHandler when auth succeeds', () {
      MockSessionHandler sessionHandler;
      var authHandler;

      setUp(() {
        sessionHandler = new MockSessionHandler();
        when(sessionHandler.handle(any, any, any)).thenReturn(okResponse);
        when(sessionHandler.authenticator).thenReturn(sessionAuthenticator);

        when(sessionAuthenticator.authenticate(any))
            .thenReturn(new Future.value(const None()));

        when(authenticator1.authenticate(any))
            .thenReturn(new Future.value(new Some(defaultAuthContext)));

        final mw =
            authenticate([authenticator1], sessionHandler: sessionHandler);
        authHandler = mw((Request r) => handler.call(r));
      });

      verifyHandlerCalledFor(
          sessionHandlerCalls(MockSessionHandler sessionHandler),
          [Request req]) {
        final f = authHandler(req != null ? req : request());
        f.then((response) {
          verify(sessionHandlerCalls(sessionHandler)).called(1);
        });
        expect(f, completes);
      }

      test("", () {
        verifyHandlerCalledFor((sh) => sh.handle(any, any, any));
      });

      test("with correct auth context", () {
        verifyHandlerCalledFor((sh) => sh.handle(defaultAuthContext, any, any));
      });

      test("with correct request", () {
        final req = request();
        verifyHandlerCalledFor((sh) => sh.handle(any, req, any), req);
      });

      test("with correct response", () {
        verifyHandlerCalledFor((sh) => sh.handle(any, any, okResponse));
      });
    });

    group(
        'does not call sessionHandler when session creation and update not allowed',
        () {
      MockSessionHandler sessionHandler;
      final authContext = new AuthenticatedContext(new Principal("fred"),
          sessionCreationAllowed: false, sessionUpdateAllowed: false);
      var authHandler;

      setUp(() {
        sessionHandler = new MockSessionHandler();
        when(sessionHandler.handle(any, any, any)).thenReturn(okResponse);
        when(sessionHandler.authenticator).thenReturn(sessionAuthenticator);

        when(sessionAuthenticator.authenticate(any))
            .thenReturn(new Future.value(const None()));

        when(authenticator1.authenticate(any))
            .thenReturn(new Future.value(new Some(authContext)));

        final mw =
            authenticate([authenticator1], sessionHandler: sessionHandler);
        authHandler = mw((Request r) => handler.call(r));
      });

      test("", () {
        final f = authHandler(request());
        f.then((response) {
          verifyNever(sessionHandler.handle(any, any, any));
        });
        expect(f, completes);
      });
    });

    group('calls sessionHandlers authenticator before other authenticators',
        () {
      MockSessionHandler sessionHandler;
      var authHandler;

      setUp(() {
        sessionHandler = new MockSessionHandler();
        when(sessionHandler.handle(any, any, any)).thenReturn(okResponse);
        when(sessionHandler.authenticator).thenReturn(sessionAuthenticator);

        when(sessionAuthenticator.authenticate(any))
            .thenReturn(new Future.value(new Some(defaultAuthContext)));

        when(authenticator1.authenticate(any))
            .thenReturn(new Future.value(new Some(defaultAuthContext)));

        final mw =
            authenticate([authenticator1], sessionHandler: sessionHandler);
        authHandler = mw((Request r) => handler.call(r));
      });

      test('', () {
        final f = authHandler(request());
        f.then((response) {
          verify(sessionAuthenticator.authenticate(any)).called(1);
          verifyNever(authenticator1.authenticate(any));
        });
        expect(f, completes);
      });
    });
  });
}

Matcher responseWithStatus(matcher) =>
    responseMatcher("statusCode", matcher, (Response r) => r.statusCode);

Matcher responseMatcher(String fieldName, matcher, Getter getter) =>
    fieldMatcher("Response", fieldName, matcher, getter);

Matcher fieldMatcher(
        String className, String fieldName, matcher, Getter getter) =>
    new FieldMatcher(className, fieldName, matcher, getter);

typedef Getter(object);

class FieldMatcher extends CustomMatcher {
  final Getter getter;

  FieldMatcher(String className, String fieldName, matcher, this.getter)
      : super("$className with $fieldName that", fieldName, matcher);

  featureValueOf(actual) => getter(actual);
}
