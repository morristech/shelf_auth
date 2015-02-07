// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.session.jwt;

import 'package:dart_jwt/dart_jwt.dart';
import 'package:logging/logging.dart';

Logger _log = new Logger('shelf_auth.session.jwt');

const String JWT_SESSION_AUTH_SCHEME = 'ShelfAuthJwtSession';

/**
 * Creates a Jwt token containing claims about a session
 */
String createSessionToken(String secret, String issuer, String subject,
    {Duration idleTimeout: const Duration(minutes: 30),
    Duration totalSessionTimeout: const Duration(days: 1), String audience}) {
  final now = new DateTime.now();

  final claimSet = new SessionClaimSet(issuer, subject, now.add(idleTimeout),
      now, audience, now.add(totalSessionTimeout));

  _log.finest('created claimSet: \n${claimSet.toJson()}');
  final jwt = new JsonWebToken.jws(claimSet, new JwaSignatureContext(secret));
  return jwt.encode();
}

/**
 * Decodes a Jwt token containing claims about a session
 */
JsonWebToken<SessionClaimSet> decodeSessionToken(String jwtToken,
    {JwsValidationContext validationContext}) {
  return new JsonWebToken.decode(jwtToken,
      validationContext: validationContext,
      claimSetParser: (Map json) => new SessionClaimSet.fromJson(json));
}

class SessionClaimSet extends JwtClaimSet {
  final DateTime totalSessionExpiry;

  SessionClaimSet(String issuer, String subject, DateTime expiry,
      DateTime issuedAt, String audience, this.totalSessionExpiry)
      : super(issuer, subject, expiry, issuedAt, audience);

  SessionClaimSet.build({String issuer, String subject, DateTime expiry,
      DateTime issuedAt, String audience, DateTime totalSessionExpiry})
      : this(issuer, subject, expiry, issuedAt, audience, totalSessionExpiry);

  SessionClaimSet.fromJson(Map json)
      : this.totalSessionExpiry = decodeIntDate(json['tse']),
        super.fromJson(json);

  Map toJson() =>
      super.toJson()..addAll({'tse': encodeIntDate(totalSessionExpiry)});

  @override
  Set<ConstraintViolation> validate(
      JwtClaimSetValidationContext validationContext) {
    return super.validate(validationContext)
      ..addAll(_validateTotalSessionExpiry(validationContext));
  }

  Set<ConstraintViolation> _validateTotalSessionExpiry(
      JwtClaimSetValidationContext validationContext) {
    if (totalSessionExpiry != null) {
      final now = new DateTime.now();
      final diff = now.difference(totalSessionExpiry);
      if (diff > validationContext.expiryTolerance) {
        return new Set()
          ..add(new ConstraintViolation(
              'JWT expired. totalSessionExpiry ($totalSessionExpiry) is more than tolerance '
              '(${validationContext.expiryTolerance}) before now ($now)'));
      }
    }

    return new Set();
  }
}

//class SessionClaimSetValidationContext extends JwtClaimSetValidationContext {
//  SessionClaimSetValidationContext({Duration expiryTolerance: const Duration(seconds: 30) })
//   : super(expiryTolerance: expiryTolerance);
//}

// TODO: these were copied from dart-jwt. Should expose them there instead

DateTime decodeIntDate(int secondsSinceEpoch) =>
    new DateTime.fromMillisecondsSinceEpoch(secondsSinceEpoch * 1000);

int encodeIntDate(DateTime dateTime) => dateTime.millisecondsSinceEpoch ~/ 1000;
