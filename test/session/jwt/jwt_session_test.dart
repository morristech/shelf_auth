// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.session.jwt.test;

import 'package:shelf_auth/src/session/jwt/jwt_session.dart';
import 'package:test/test.dart';
import 'package:dart_jwt/dart_jwt.dart';

main() {
  group('encode decode rountrip', () {
    final issuer = 'da issuer';
    final subject = 'el subjecto';
    const String sessionId = 'id1234';

    String token() =>
        createSessionToken('secret sauce', issuer, subject, sessionId);
    JsonWebToken<SessionClaimSet> roundTrip() => decodeSessionToken(token());
    SessionClaimSet claimSet() => roundTrip().claimSet;

    test('has matching issuer', () {
      expect(claimSet().issuer, equals(issuer));
    });

    test('has matching subject', () {
      expect(claimSet().subject, equals(subject));
    });

    test('has matching sessionId', () {
      expect(claimSet().sessionIdentifier, equals(sessionId));
    });

    test('has expected issuedAt', () {
      expect(claimSet().issuedAt.millisecondsSinceEpoch,
          closeTo(new DateTime.now().millisecondsSinceEpoch, 1200));
    });

    test('has expected expiry offset', () {
      expect(claimSet().expiry.difference(claimSet().issuedAt),
          equals(const Duration(minutes: 30)));
    });

    test('has expected expiry offset', () {
      expect(claimSet().totalSessionExpiry.difference(claimSet().issuedAt),
          equals(const Duration(days: 1)));
    });
  });
}
