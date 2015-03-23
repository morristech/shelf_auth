// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisation.test;

import 'package:shelf_auth/shelf_auth.dart';
import 'package:shelf_auth/src/authentication_impl.dart';

import 'package:unittest/unittest.dart';
import 'package:mockito/mockito.dart';
import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:shelf_exception_response/exception.dart';

class MockAuthoriser extends Mock implements Authoriser {
  noSuchMethod(_) => super.noSuchMethod(_);
}

//typedef Handler(Request request);
abstract class HandlerClass {
  dynamic call(Request request) {
    return null;
  }
}

class MockHandler extends Mock implements HandlerClass {
  noSuchMethod(_) => super.noSuchMethod(_);
}

class MockSessionHandler extends Mock implements SessionHandler {
  noSuchMethod(_) => super.noSuchMethod(_);
}

main() {
  MockAuthoriser authoriser1;
  MockAuthoriser authoriser2;
  MockHandler handler;

  Request request() => new Request('GET', Uri.parse('https://blah/foo'));
  Request requestAuthenticated() => request().change(
      context: {
    SHELF_AUTH_REQUEST_CONTEXT: new AuthenticatedContext(new Principal('fred'))
  });
  final okResponse = new Response.ok('sweet');

  setUp(() {
    authoriser1 = new MockAuthoriser();
    authoriser2 = new MockAuthoriser();
    handler = new MockHandler();
    when(handler.call(argThat(new isInstanceOf<Request>())))
        .thenReturn(okResponse);
  });

  group('authorisationMiddleware', () {
    group('when passed an empty list of authorisers', () {
      var middlewareHandler;
      setUp(() {
        final mw = authorise([]);
        middlewareHandler = mw(handler);
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

        test("calls handler", () {
          verify(handler.call(any)).called(1);
        });

        test('returns 200 response', () {
          expect(response, responseWithStatus(200));
        });
      });
    });

    group('when all authorisers return true', () {
      var middlewareHandler;

      setUp(() {
        when(authoriser1.isAuthorised(any)).thenReturn(new Future.value(true));
        when(authoriser2.isAuthorised(any)).thenReturn(new Future.value(true));
        final mw = authorise([authoriser1, authoriser2]);
        middlewareHandler = mw(handler);
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

        test("calls handler", () {
          verify(handler.call(any)).called(1);
        });

        test("calls both authorisers", () async {
          verify(authoriser1.isAuthorised(any)).called(1);
          verify(authoriser2.isAuthorised(any)).called(1);
        });

        test('returns 200 response', () {
          expect(response, responseWithStatus(200));
        });
      });
    });

    group('when first authorisers return false', () {
      var middlewareHandler;
      setUp(() {
        when(authoriser1.isAuthorised(any)).thenReturn(new Future.value(false));
        when(authoriser2.isAuthorised(any)).thenReturn(new Future.value(true));
        final mw = authorise([authoriser1, authoriser2]);
        middlewareHandler = mw(handler);
      });

      test('and request unauthenticated throws an UnauthorizedException', () {
        expect(middlewareHandler(request()),
            throwsA(new isInstanceOf<UnauthorizedException>()));
      });

      test('and request authenticated throws a ForbiddenException', () {
        expect(middlewareHandler(requestAuthenticated()),
            throwsA(new isInstanceOf<ForbiddenException>()));
      });

      test("calls first authoriser", () async {
        try {
          await middlewareHandler(request());
        } catch (e) {
          verify(authoriser1.isAuthorised(any)).called(1);
        }
      });

      test("doesn't call second authoriser", () async {
        try {
          await middlewareHandler(request());
        } catch (e) {
          verifyNever(authoriser2.isAuthorised(any));
        }
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
