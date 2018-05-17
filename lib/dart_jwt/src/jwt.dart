library jwt.jwt;

import 'package:pointycastle/pointycastle.dart';

import 'jose.dart';
import 'jwa.dart';
import 'jws.dart';
import 'jwt_claimset.dart';
import 'validation_constraint.dart';

export 'jwt_claimset.dart';

/**
 * Represents a [JSON Web Token](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-19)
 */
abstract class JsonWebToken
    implements JoseObject {
  /// The payload of a JWT is its claim set
  get claimSet;

  factory JsonWebToken.decode(String jwtToken,
      {JwsValidationContext validationContext,
      ClaimSetParser claimSetParser: openIdClaimSetParser}) {
    // TODO: figure out if the jwt is in a jws or jwe structure. Assuming jws for now
    try {
      return new JwtInJws.decode(jwtToken, validationContext, claimSetParser);
    } on FormatException catch (e) {
      throw new ArgumentError.value(
          jwtToken, 'jwtToken', 'Could not parse jwtToken - ${e.message}');
    }
  }

  factory JsonWebToken.jws(claimSet, JwaSignatureContext signatureContext,
      {JsonWebAlgorithm algorithm: JsonWebAlgorithm.HS256}) {
    return new JwtInJws(claimSet, signatureContext, algorithm);
  }

  // TODO: this doesn't make sense at this level but need to expose somehow.
  // What makes sense for jwe?
  Set<ConstraintViolation> validate(JwtValidationContext validationContext);

  /// Encodes the JWT into a string. The form differs depending on what
  /// container (JWS or JWE) houses the JWT.
  /// This is the form that is sent across the wire
  String encode();
}

/**
 * Represents a [JsonWebToken] that is encoded within a [JsonWebSignature]
 */
class JwtInJws extends JsonWebSignature
    implements JsonWebToken {
  get claimSet => payload;

  JwtInJws._internal(
      JwsHeader header, claimSet, JwsSignature signature, String signingInput)
      : super(header, claimSet, signature, signingInput);

  factory JwtInJws.decode(String jwtToken,
      JwsValidationContext validationContext, ClaimSetParser claimSetParser) {
    final base64Segs = jwtToken.split('.');
    if (base64Segs.length != 3)
      throw new ArgumentError(
          "JWS tokens must be in form '<header>.<payload>.<signature>'.\n"
          "Value: '$jwtToken' is invalid");

    final header = new JwsHeader.decode(base64Segs.first);
    final claimSet =
        claimSetParser(Base64EncodedJson.decodeToJson(base64Segs.elementAt(1)));
    final signature = new JwsSignature.decode(base64Segs.elementAt(2));

    final signingInput = jwtToken.substring(0, jwtToken.lastIndexOf('.'));

    final JsonWebToken jwt =
        new JwtInJws._internal(header, claimSet, signature, signingInput);

    if (validationContext != null) {
      final Set<ConstraintViolation> violations =
          jwt.validate(validationContext);
      if (violations.isNotEmpty) {
        throw new ConstraintViolations('jwt is invalid', violations);
      }
    }

    return jwt;
  }

  factory JwtInJws(claimSet, JwaSignatureContext signatureContext,
      JsonWebAlgorithm algorithm) {
    final JwsHeader header =
        new JwsHeader.build(type: JwsType.JWT, algorithm: algorithm);
    final String signingInput = JoseObject.encodeSegments([header, claimSet]);

    final JwsSignature signature = new JwsSignature.create(
        signingInput, header.algorithm, signatureContext);

    return new JwtInJws._internal(header, claimSet, signature, signingInput);
  }

  @override
  Set<ConstraintViolation> validatePayload(covariant
          JwtValidationContext validationContext) =>
      claimSet.validate(validationContext.claimSetValidationContext);
}

class JwtValidationContext extends JwsValidationContext {
  final JwtClaimSetValidationContext claimSetValidationContext;

  JwtValidationContext(
      JwaSignatureContext signatureContext, this.claimSetValidationContext)
      : super(signatureContext);

  JwtValidationContext.withSharedSecret(String sharedSecret)
      : this(new JwaSymmetricKeySignatureContext(sharedSecret),
            new JwtClaimSetValidationContext());

  JwtValidationContext.withRsaPublicKey(RSAPublicKey rsaPublicKey)
      : this(new JwaRsaSignatureContext.withKeys(rsaPublicKey: rsaPublicKey),
            new JwtClaimSetValidationContext());
}

typedef JwtClaimSet ClaimSetParser(Map json);

JwtClaimSet openIdClaimSetParser(Map json) =>
    new OpenIdJwtClaimSet.fromJson(json);

JwtClaimSet mapClaimSetParser(Map json) => new MapJwtClaimSet.fromJson(json);
