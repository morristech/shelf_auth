library jwt.jws;

import 'dart:convert';

import 'jose.dart';
import 'jwa.dart';
import 'util.dart';
import 'validation_constraint.dart';

typedef JosePayload PayloadParser(Map json);

/**
 * Represents a [JSON Web Signature](http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-24).
 *
 * A Jws has a [header] that describes the [JsonWebAlgorithm] used to generate
 * the [signature]
 */
abstract class JsonWebSignature
    extends JoseObject {
  final JwsSignature signature;
  final String _signingInput;

  Iterable<Base64EncodedData> get segments => [header, payload, signature];

  JsonWebSignature(
      JwsHeader header, payload, this.signature, this._signingInput)
      : super(header, payload);

  Set<ConstraintViolation> validate(JwsValidationContext validationContext) {
    return validateSignature(validationContext)
      ..addAll(validatePayload(validationContext));
  }

  Set<ConstraintViolation> validateSignature(
      JwsValidationContext validationContext) {
    if (!validationContext.supportedAlgorithms.contains(header.algorithm)) {
      return new Set.from([
        new ConstraintViolation('unsupported algorithm ${header.algorithm}')
      ]);
    }

    return signature.validate(
        _signingInput, header.algorithm, validationContext.signatureContext);
  }

  Set<ConstraintViolation> validatePayload(
      JwsValidationContext validationContext);
}

/// A header for a [JsonWebSignature] defining the [type] of JWS object and
/// [algorithm] used in the signature
class JwsHeader extends JoseHeader {
  final JwsType type;
  final JsonWebAlgorithm algorithm;
  final Uri jwkSetUrl;
  final String keyId;
  final String x509CertificateThumbprint;

  @deprecated
  JwsHeader(JwsType type, JsonWebAlgorithm algorithm)
      : this.build(type: type, algorithm: algorithm);

  JwsHeader.build(
      {JwsType type: JwsType.JWT,
      this.algorithm,
      this.jwkSetUrl,
      this.keyId,
      this.x509CertificateThumbprint})
      : this.type = type != null ? type : JwsType.JWT {
    checkNotNull(this.type);
    checkNotNull(algorithm);
  }

  JwsHeader._fromJson(JsonParser p)
      : this.build(
            type: p.get('typ', (v) => JwsType.lookup(v)),
            algorithm: p.get('alg', (v) => JsonWebAlgorithm.lookup(v)),
            jwkSetUrl: p.get('jku', (v) => Uri.parse(v)),
            keyId: p.get('kid'),
            x509CertificateThumbprint: p.get('x5t'));

  JwsHeader.fromJson(Map json) : this._fromJson(new JsonParser(json));

  JwsHeader.decode(String base64String)
      : this.fromJson(Base64EncodedJson.decodeToJson(base64String));

  Map toJson() => buildJson({'alg': algorithm.name, 'typ': type.name})
      .add('jku', jwkSetUrl, (u) => u.toString())
      .add('kid', keyId)
      .add('x5t', x509CertificateThumbprint)
      .build();

  String toString() => 'JwsHeader[type=$type, algorithm=$algorithm]';

  @override
  Iterable<int> get decodedBytes => JSON.encode(toJson()).codeUnits;
}

/// Encapsulates the actual signature for a [JsonWebSignature]
class JwsSignature extends Base64EncodedData {
  final List<int> signatureBytes;

  JwsSignature(this.signatureBytes);

  JwsSignature.create(String signingInput, JsonWebAlgorithm algorithm,
      JwaSignatureContext signatureContext)
      : signatureBytes = algorithm.sign(signingInput, signatureContext);

  JwsSignature.decode(String base64String)
      : this(Base64EncodedData.decodeToBytes(base64String));

  Set<ConstraintViolation> validate(String signingInput,
      JsonWebAlgorithm algorithm, JwaSignatureContext signatureContext) {
    return algorithm.validateSignature(
        signingInput, signatureBytes, signatureContext);
  }

  @override
  Iterable<int> get decodedBytes => signatureBytes;
}

/// The type of [JsonWebSignature] object
class JwsType {
  final String name;
  final bool isSupported;

  const JwsType._internal(this.name, this.isSupported);

  static JwsType lookup(String name) {
    checkNotNull(name);
    var t = _supportedTypes[name.toUpperCase()];
    if (t == null) {
      t = new JwsType._internal(name, false);
    }
    return t;
  }

  static const JwsType JWT = const JwsType._internal('JWT', true);

  static Map<String, JwsType> _supportedTypes = {
    null: JWT,
    'JWT': JWT,
  };

  String toString() => '$name';
}

typedef JwsValidationContext JwsValidationContextFactory();

class JwsValidationContext {
  final JwaSignatureContext signatureContext;
  final Set<JsonWebAlgorithm> supportedAlgorithms;

  JwsValidationContext(this.signatureContext,
      {Set<JsonWebAlgorithm> supportedAlgorithms})
      : this.supportedAlgorithms = supportedAlgorithms != null
            ? supportedAlgorithms
            : new Set.from([JsonWebAlgorithm.HS256]);
}

_noopXform(v) => v;

JsonBuilder buildJson([Map json]) => new JsonBuilder(json);

class JsonBuilder {
  final Map _json;

  JsonBuilder(Map json) : this._json = json != null ? json : {};

  JsonBuilder add(String key, value, [transform(v) = _noopXform]) {
    if (value != null) {
      _json[key] = transform(value);
    }
    return this;
  }

  Map build() => _json;
}

class JsonParser {
  final Map _json;

  JsonParser(this._json);

  get(String key, [transform(v) = _noopXform]) {
    final value = _json[key];
    return value != null ? transform(value) : null;
  }
}
