// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisation.authenticatedonly.test;

import 'package:shelf/shelf.dart';
import 'package:shelf_auth/src/authorisers/authenticated_only_authoriser.dart';
import 'package:test/test.dart';
import 'package:shelf_auth/src/authentication_impl.dart';
import 'package:shelf_auth/src/context.dart';

main() {
  Request requestUnauthenticated() =>
      new Request('GET', Uri.parse('http://foo.bar/blah'));

  Request requestAuthenticated() => requestUnauthenticated().change(
      context: {
    SHELF_AUTH_REQUEST_CONTEXT: new AuthenticatedContext(new Principal('fred'))
  });

  AuthenticatedOnlyAuthoriser authoriser;

  group('isAuthorised', () {
    setUp(() {
      authoriser = new AuthenticatedOnlyAuthoriser();
    });

    group('when user unauthenticated', () {
      test('completes', () {
        expect(authoriser.isAuthorised(requestUnauthenticated()), completes);
      });

      test('completes with false', () {
        expect(authoriser.isAuthorised(requestUnauthenticated()),
            completion(false));
      });
    });

    group('when user authenticated', () {
      test('completes', () {
        expect(authoriser.isAuthorised(requestAuthenticated()), completes);
      });

      test('completes with true', () {
        expect(
            authoriser.isAuthorised(requestAuthenticated()), completion(true));
      });
    });
  });
}
