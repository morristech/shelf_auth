// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisation.authwithexclusions.test;

import 'package:shelf/shelf.dart';
import 'package:shelf_auth/src/authorisers/authoriser_with_exclusions.dart';
import 'package:test/test.dart';
import 'package:shelf_auth/src/authorisation.dart';
import 'package:mockito/mockito.dart';
import 'dart:async';

class MockAuthoriser extends Mock implements Authoriser {
  noSuchMethod(_) => super.noSuchMethod(_);
}

//typedef bool RequestWhiteList(Request r);
class RequestWhiteListClass {
  bool call(Request r) => true;
}

class MockRequestWhiteList extends Mock implements RequestWhiteListClass {
  noSuchMethod(Invocation i) => super.noSuchMethod(i);
}

main() {
  Request request() => new Request('GET', Uri.parse('http://foo.bar/blah'));

  Authoriser authoriser;
  MockRequestWhiteList whitelist;
  MockAuthoriser realAuthoriser;

  group('isAuthorised', () {
    setUp(() {
      realAuthoriser = new MockAuthoriser();
      whitelist = new MockRequestWhiteList();
      authoriser = new AuthoriserWithExclusions(whitelist, realAuthoriser);
    });

    group('when whitelist returns true', () {
      setUp(() {
        when(whitelist.call(any)).thenReturn(true);
      });

      test('completes', () {
        expect(authoriser.isAuthorised(request()), completes);
      });

      test('completes with true', () {
        expect(authoriser.isAuthorised(request()), completion(true));
      });

      test('doesnt call realAuthoriser', () {
        authoriser.isAuthorised(request()).then((_) {
          verifyNever(realAuthoriser.isAuthorised(any));
        });
      });
    });

    group('when whitelist returns false', () {
      setUp(() {
        when(whitelist.call(any)).thenReturn(false);
      });

      group('when realAuthoriser returns false', () {
        setUp(() {
          when(realAuthoriser.isAuthorised(any))
              .thenReturn(new Future.value(false));
        });

        test('completes', () {
          expect(authoriser.isAuthorised(request()), completes);
        });

        test('completes with false', () {
          expect(authoriser.isAuthorised(request()), completion(false));
        });

        test('does call realAuthoriser', () {
          authoriser.isAuthorised(request()).then((_) {
            verify(realAuthoriser.isAuthorised(any)).called(1);
          });
        });
      });
      group('when realAuthoriser returns true', () {
        setUp(() {
          when(realAuthoriser.isAuthorised(any))
              .thenReturn(new Future.value(true));
        });

        test('completes', () {
          expect(authoriser.isAuthorised(request()), completes);
        });

        test('completes with true', () {
          expect(authoriser.isAuthorised(request()), completion(true));
        });

        test('does call realAuthoriser', () {
          authoriser.isAuthorised(request()).then((_) {
            verify(realAuthoriser.isAuthorised(any)).called(1);
          });
        });
      });
    });
  });
}
