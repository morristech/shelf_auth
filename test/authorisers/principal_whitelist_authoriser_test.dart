// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisers.principal.whitelist.test;

import 'package:shelf/shelf.dart';
import 'package:shelf_auth/src/authorisers/principal_whitelist_authoriser.dart';
import 'package:shelf_auth/src/authentication_impl.dart';
import 'package:test/test.dart';
import 'package:mockito/mockito.dart';
import 'package:shelf_auth/src/context.dart';

//typedef bool PrincipalWhiteList(Principal p);
abstract class PrincipalWhiteListClass {
  bool call(Principal p) => false;
}

class MockPrincipalWhiteList extends Mock implements PrincipalWhiteListClass {
}

main() {
  Request requestUnauthenticated() =>
      new Request('GET', Uri.parse('http://foo.bar/blah'));

  Request requestAuthenticated() => requestUnauthenticated().change(context: {
        SHELF_AUTH_REQUEST_CONTEXT:
            new AuthenticatedContext(new Principal('fred'))
      });
//  return new Option(request.context[SHELF_AUTH_REQUEST_CONTEXT]);

  PrincipalWhitelistAuthoriser authoriser;
  MockPrincipalWhiteList _whitelist;

  bool whitelist(Principal p) => _whitelist.call(p);

  setUp(() {
    _whitelist = new MockPrincipalWhiteList();
  });


  group('isAuthorised', () {
    group('when user unauthenticated', () {
      setUp(() {
        when(_whitelist.call(any)).thenReturn(true);
      });

      group('and denyUnauthenticated is false', () {
        setUp(() {
          authoriser = new PrincipalWhitelistAuthoriser(whitelist,
              denyUnauthenticated: false);
        });
        test('completes', () {
          expect(authoriser.isAuthorised(requestUnauthenticated()), completes);
        });

        test('completes with true', () {
          expect(authoriser.isAuthorised(requestUnauthenticated()),
              completion(true));
        });
      });

      group('and denyUnauthenticated is true', () {
        setUp(() {
          authoriser = new PrincipalWhitelistAuthoriser(whitelist,
              denyUnauthenticated: true);
        });
        test('completes', () {
          expect(authoriser.isAuthorised(requestUnauthenticated()), completes);
        });

        test('completes with false', () {
          expect(authoriser.isAuthorised(requestUnauthenticated()),
              completion(false));
        });
      });
    });

    group('when user authenticated', () {
      group('and user in whitelist', () {
        setUp(() {
          authoriser = new PrincipalWhitelistAuthoriser(whitelist);
          when(_whitelist.call(any)).thenReturn(true);
        });

        test('completes', () {
          expect(authoriser.isAuthorised(requestAuthenticated()), completes);
        });

        test('completes with true', () {
          expect(authoriser.isAuthorised(requestAuthenticated()),
              completion(true));
        });
      });

      group('and not user in whitelist', () {
        setUp(() {
          authoriser = new PrincipalWhitelistAuthoriser(whitelist);
          when(_whitelist.call(any)).thenReturn(false);
        });
        test('completes', () {
          expect(authoriser.isAuthorised(requestAuthenticated()), completes);
        });

        test('completes with false', () {
          expect(authoriser.isAuthorised(requestAuthenticated()),
              completion(false));
        });
      });
    });
  });
}
