// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisation.sameorigin.test;

import 'package:shelf/shelf.dart';
import 'package:shelf_auth/src/authorisers/same_origin_authoriser.dart';
import 'package:unittest/unittest.dart';

main() {
  requestNoReferer() => new Request('GET', Uri.parse('http://foo.bar/blah'));

  requestSameOrigin() => new Request('GET', Uri.parse('http://foo.bar/blah'),
      headers: {'referer': 'http://foo.bar/fum'});

  requestDifferentOrigin() => new Request(
      'GET', Uri.parse('http://foo.bar/blah'),
      headers: {'referer': 'http://blah.blah/fum'});

  final authoriser = new SameOriginAuthoriser();

  group('isAuthorised', () {
    group('when referer header is present', () {
      group('and matches request origin', () {
        test('completes', () {
          expect(authoriser.isAuthorised(requestSameOrigin()), completes);
        });

        test('completes with true', () {
          expect(
              authoriser.isAuthorised(requestSameOrigin()), completion(true));
        });
      });

      group('and does not match request origin', () {
        test('completes', () {
          expect(authoriser.isAuthorised(requestDifferentOrigin()), completes);
        });

        test('returns false', () {
          expect(authoriser.isAuthorised(requestDifferentOrigin()),
              completion(false));
        });
      });
    });

    group('when no refererer header is present', () {
      test('completes', () {
        expect(authoriser.isAuthorised(requestNoReferer()), completes);
      });

      test('completes with false', () {
        expect(authoriser.isAuthorised(requestNoReferer()), completion(false));
      });
    });
  });
}
