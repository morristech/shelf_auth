// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.session.jwt;

import '../../../dart_jwt/dart_jwt.dart';
import 'package:logging/logging.dart';
import '../../preconditions.dart';
import 'dart:async';
import 'package:option/option.dart';
import 'package:shelf_auth/src/context.dart';
import 'package:uuid/uuid.dart';
import '../../util.dart';

Logger _log = new Logger('shelf_auth.session.jwt');

const String JWT_SESSION_AUTH_SCHEME = 'ShelfAuthJwtSession';

typedef Future<Option<P>> UserLookupBySessionClaimSet<P extends Principal,
    CS extends SessionClaimSet>(CS claimSet);

typedef JsonWebToken<CS> SessionTokenDecoder<CS extends SessionClaimSet>(
    String jwtToken,
    {JwsValidationContext validationContext});

final JwtCodec<SessionClaimSet> jwtSessionCodec = new JwtCodec.def((Map json,
        // TODO: validationContext not used. Is that OK?
        {JwsValidationContext validationContext}) =>
    new SessionClaimSet.fromJson(json));

class JwtSessionAuthorizationHeader extends AuthorizationHeader {
  JwtSessionAuthorizationHeader(String credentials)
      : super(JWT_SESSION_AUTH_SCHEME, credentials);
}

/**
 * Creates a Jwt token containing claims about a session
 */
@deprecated
String createSessionToken(
    String secret, String issuer, String subject, String sessionIdentifier,
    {Duration idleTimeout: const Duration(minutes: 30),
    Duration totalSessionTimeout: const Duration(days: 1),
    String audience}) {
  final claimSet = new SessionClaimSet.create(issuer, subject,
      idleTimeout: idleTimeout,
      totalSessionTimeout: totalSessionTimeout,
      sessionIdentifier: sessionIdentifier,
      audience: audience);

  _log.finest('created claimSet: \n${claimSet.toJson()}');
  final jwt = new JsonWebToken.jws(
      claimSet, new JwaSymmetricKeySignatureContext(secret));
  return jwt.encode();
}

/**
 * Decodes a Jwt token containing claims about a session
 */
@deprecated
JsonWebToken<SessionClaimSet> decodeSessionToken(String jwtToken,
    {JwsValidationContext validationContext}) {
  return new JsonWebToken.decode(jwtToken,
      validationContext: validationContext,
      claimSetParser: (Map json) => new SessionClaimSet.fromJson(json));
}

class SessionClaimSet extends OpenIdJwtClaimSet {
  final DateTime totalSessionExpiry;
  final String sessionIdentifier;

  SessionClaimSet(
      String issuer,
      String subject,
      DateTime expiry,
      DateTime issuedAt,
      String audience,
      this.sessionIdentifier,
      this.totalSessionExpiry)
      : super(issuer, subject, expiry, issuedAt, [audience]) {
    ensure(sessionIdentifier, isNotNull);
    ensure(totalSessionExpiry, isNotNull);
  }

  SessionClaimSet.build(
      {String issuer,
      String subject,
      DateTime expiry,
      DateTime issuedAt,
      String audience,
      DateTime totalSessionExpiry,
      String sessionIdentifier})
      : this(issuer, subject, expiry, issuedAt, audience, sessionIdentifier,
            totalSessionExpiry);

  SessionClaimSet._std(
      DateTime now,
      String issuer,
      String subject,
      String sessionIdentifier,
      Duration idleTimeout,
      Duration totalSessionTimeout,
      String audience)
      : this(issuer, subject, now.add(idleTimeout), now, audience,
            sessionIdentifier, now.add(totalSessionTimeout));

  SessionClaimSet.create(String issuer, String subject,
      {String sessionIdentifier,
      Duration idleTimeout: const Duration(minutes: 30),
      Duration totalSessionTimeout: const Duration(days: 1),
      String audience})
      : this._std(
            new DateTime.now(),
            issuer,
            subject,
            sessionIdentifier != null ? sessionIdentifier : new Uuid().v4(),
            idleTimeout != null ? idleTimeout : const Duration(minutes: 30),
            totalSessionTimeout != null
                ? totalSessionTimeout
                : const Duration(days: 1),
            audience);

  SessionClaimSet.fromJson(Map json)
      : this.totalSessionExpiry = decodeIntDate(json['tse']),
        this.sessionIdentifier = json['sid'],
        super.fromJson(json) {
    ensure(sessionIdentifier, isNotNull);
    ensure(totalSessionExpiry, isNotNull);
  }

  Map toJson() => super.toJson()
    ..addAll(
        {'sid': sessionIdentifier, 'tse': encodeIntDate(totalSessionExpiry)});

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
// TODO: these were copied from dart-jwt. Should expose them there instead

DateTime decodeIntDate(int secondsSinceEpoch) => secondsSinceEpoch != null
    ? new DateTime.fromMillisecondsSinceEpoch(secondsSinceEpoch * 1000)
    : null;

int encodeIntDate(DateTime dateTime) => dateTime.millisecondsSinceEpoch ~/ 1000;
