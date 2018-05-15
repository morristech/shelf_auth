library jwt.jwa;

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';
import 'package:crypto/crypto.dart';
import 'package:logging/logging.dart';

import 'util.dart';
import 'validation_constraint.dart';

Logger _log = new Logger("jwt.jwa");

/**
 * Represents a [JSON Web Algorithm](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-25)
 */
abstract class JsonWebAlgorithm<T extends JwaSignatureContext> {
  final String name;

  const JsonWebAlgorithm._internal(this.name);

  static JsonWebAlgorithm lookup(String name) {
    return checkNotNull(_supportedAlgorithms[name]);
  }

  static const JsonWebAlgorithm HS256 = const _HS256JsonWebAlgorithm();
  static const JsonWebAlgorithm RS256 = const _RS256JsonWebAlgorithm();

  static Map<String, JsonWebAlgorithm> _supportedAlgorithms = {
    'HS256': HS256,
    'RS256': RS256
  };

  String toString() => '$name';

  List<int> sign(String signingInput, T signatureContext) {
    /*
     * TODO: ugly. Because I'm base 64 decoding the signature from the request I need
     * to reencode here. Better to avoid the decode in the first place
     */
    final raw = _rawSign(signingInput, signatureContext);
    final sig = bytesToBase64(raw, stringPadding: false);
    _log.finest('signature is $sig');
    return base64ToBytes(sig);
  }

  Set<ConstraintViolation> validateSignature(
      String signingInput, List<int> signatureBytes, T signatureContext) {
    return _internalValidateSignature(
        signingInput, signatureBytes, signatureContext);
  }

  List<int> _rawSign(String signingInput, T validationContext);
  Set<ConstraintViolation> _internalValidateSignature(
      String signingInput, List<int> signatureBytes, T signatureContext);
}

abstract class JwaSignatureContext {}

class JwaSymmetricKeySignatureContext extends JwaSignatureContext {
  final String symmetricKey;

  JwaSymmetricKeySignatureContext(this.symmetricKey);
}

class JwaRsaSignatureContext extends JwaSignatureContext {
  final RSAPrivateKey rsaPrivateKey;
  final RSAPublicKey rsaPublicKey;

  JwaRsaSignatureContext(this.rsaPublicKey, this.rsaPrivateKey);
  JwaRsaSignatureContext.withKeys({this.rsaPublicKey, this.rsaPrivateKey});
}

class _HS256JsonWebAlgorithm
    extends JsonWebAlgorithm<JwaSymmetricKeySignatureContext> {
  const _HS256JsonWebAlgorithm() : super._internal('HS256');

  @override
  List<int> _rawSign(
      String signingInput, JwaSymmetricKeySignatureContext signatureContext) {
    _log.finest(
        'signingInput: $signingInput, sharedSecret: ${signatureContext.symmetricKey}');
    final hmac = new Hmac(sha256, signatureContext.symmetricKey.codeUnits);

    return hmac.convert(signingInput.codeUnits).bytes;
  }

  @override
  Set<ConstraintViolation> _internalValidateSignature(
      String signingInput,
      List<int> signatureBytes,
      JwaSymmetricKeySignatureContext signatureContext) {
    List<int> result = this.sign(signingInput, signatureContext);

    return _signaturesMatch(result, signatureBytes)
        ? new Set.identity()
        : (new Set()
          ..add(new ConstraintViolation('signatures do not match. ' +
              'Received: ${bytesToBase64(signatureBytes)} vs ' +
              'Calculated: ${bytesToBase64(result)}')));
  }

  bool _signaturesMatch(List<int> result, List<int> signatureBytes) {
    if (signatureBytes.length != result.length) return false;

    var r = 0;
    for (int i = 0; i < signatureBytes.length; i++) {
      r |= signatureBytes.elementAt(i) ^ result.elementAt(i);
    }
    return r == 0;
  }
}

class _RS256JsonWebAlgorithm extends JsonWebAlgorithm<JwaRsaSignatureContext> {
  const _RS256JsonWebAlgorithm() : super._internal('RS256');

  @override
  List<int> _rawSign(
      String signingInput, JwaRsaSignatureContext signatureContext) {
    if (signatureContext.rsaPrivateKey == null)
      throw new ArgumentError.notNull("signatureContext.rsaPrivateKey");

    var privParams = new PrivateKeyParameter(signatureContext.rsaPrivateKey);
    var signParams =
        new ParametersWithRandom(privParams, new SecureRandom("AES/CTR/PRNG"));
    var signer = new Signer("SHA-256/RSA")..init(true, signParams);
    RSASignature rsaSignature = signer
        .generateSignature(new Uint8List.fromList(signingInput.codeUnits));
    return rsaSignature.bytes;
  }

  @override
  Set<ConstraintViolation> _internalValidateSignature(String signingInput,
      List<int> signatureBytes, JwaRsaSignatureContext signatureContext) {
    if (signatureContext.rsaPublicKey == null)
      throw new ArgumentError.notNull("signatureContext.rsaPublicKey");

    var publicParams = new PublicKeyParameter(signatureContext.rsaPublicKey);
    var signParams = new ParametersWithRandom(
        publicParams, new SecureRandom("AES/CTR/PRNG"));
    var signer = new Signer("SHA-256/RSA")..init(false, signParams);
    var rsaSignature = new RSASignature(new Uint8List.fromList(signatureBytes));
    var ok = signer.verifySignature(
        new Uint8List.fromList(signingInput.codeUnits), rsaSignature);
    return ok
        ? new Set.identity()
        : (new Set()
          ..add(new ConstraintViolation('RSA signature failed validation.')));
  }
}
