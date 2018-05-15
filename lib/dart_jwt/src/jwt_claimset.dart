library jwt.jwt_claimset;

import 'dart:convert';

import 'jose.dart';
import 'util.dart';
import 'validation_constraint.dart';

abstract class JwtClaimSet extends JosePayload {
  Set<ConstraintViolation> validate(
      JwtClaimSetValidationContext validationContext);
}

typedef Set<ConstraintViolation> MapClaimSetValidator(
    Map claimSetJson, JwtClaimSetValidationContext validationContext);

Set<ConstraintViolation> _noopValidator(
        Map claimSetJson, JwtClaimSetValidationContext validationContext) =>
    new Set();

class MapJwtClaimSet extends JwtClaimSet {
  final Map json;
  final MapClaimSetValidator validator;

  MapJwtClaimSet(this.json, {this.validator: _noopValidator});

  MapJwtClaimSet.fromJson(this.json, {this.validator: _noopValidator});

  Map toJson() => json;

  Map toMap() => json;

  Set<ConstraintViolation> validate(
          JwtClaimSetValidationContext validationContext) =>
      validator(json, validationContext);
}

class OpenIdJwtClaimSet extends JwtClaimSet {
  final String issuer;
  final List<String> audience;
  final String subject;
  final DateTime expiry;
  final DateTime issuedAt;

  OpenIdJwtClaimSet(
      this.issuer, this.subject, this.expiry, this.issuedAt, this.audience);

  OpenIdJwtClaimSet.build(
      {this.issuer, this.subject, this.expiry, this.issuedAt, this.audience});

  OpenIdJwtClaimSet.fromJson(Map json)
      : issuer = json['iss'],
        subject = json['sub'],
        expiry = decodeIntDate(json['exp']),
        issuedAt = decodeIntDate(json['iat']),
        audience = (json['aud'] is String ? [json['aud']] : json['aud']);

  OpenIdJwtClaimSet copy(
      {String issuer,
      List<String> audience,
      String subject,
      DateTime expiry,
      DateTime issuedAt}) {
    return new OpenIdJwtClaimSet(
        issuer != null ? issuer : this.issuer,
        subject != null ? subject : this.subject,
        expiry != null ? expiry : this.expiry,
        issuedAt != null ? issuedAt : this.issuedAt,
        audience != null ? audience : this.audience);
  }

  Map toJson() => {
        'iat': encodeIntDate(issuedAt),
        'exp': encodeIntDate(expiry),
        'iss': issuer,
        'sub': subject,
        'aud': audience
      };

  String toString() => JSON.encode(this);

  Set<ConstraintViolation> validate(
      JwtClaimSetValidationContext validationContext) {
    final now = new DateTime.now();
    final diff = now.difference(expiry);
    if (diff > validationContext.expiryTolerance) {
      return new Set()
        ..add(new ConstraintViolation(
            'JWT expired. Expiry ($expiry) is more than tolerance '
            '(${validationContext.expiryTolerance}) before now ($now)'));
    }

    return new Set.identity();
  }
}

class JwtClaimSetValidationContext {
  final Duration expiryTolerance;

  const JwtClaimSetValidationContext(
      {this.expiryTolerance: const Duration(seconds: 30)});
}
