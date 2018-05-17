library jwt.codec;

import 'dart:convert';

import 'jose.dart';
import 'jws.dart';
import 'jwt.dart';
import 'jwt_claimset.dart';

typedef JsonWebToken JwtTokenDecoder<H extends JoseHeader,
    CS extends JwtClaimSet>(String jwtToken, {JwsValidationContext validationContext});

typedef CS JwtClaimSetDecoder<CS extends JwtClaimSet>(Map claimSetJson,
    {JwsValidationContext validationContext});

JwtTokenDecoder<JoseHeader, JwtClaimSet> defaultJwtTokenDecoder(
    JwtClaimSetDecoder claimSetDecoder) {
  return (String jwtToken, {JwsValidationContext validationContext}) =>
      new JsonWebToken.decode(jwtToken,
          validationContext: validationContext,
          claimSetParser: claimSetDecoder);
}

class JwtCodec<H extends JoseHeader, CS extends JwtClaimSet>
    extends Codec<JsonWebToken, String> {
  final Converter<JsonWebToken, String> encoder =
      new JwtEncoder<H, CS>();
  final Converter<String, JsonWebToken> decoder;

  JwtCodec(this.decoder);

  JwtCodec.simple(JwtTokenDecoder<H, CS> decoder,
      {JwsValidationContextFactory contextFactory})
      : this(new JwtDecoder(decoder, contextFactory));

  JwtCodec.def(JwtClaimSetDecoder<CS> decoder,
      {JwsValidationContextFactory contextFactory})
      : this(new JwtDecoder(defaultJwtTokenDecoder(decoder), contextFactory));
}

class JwtDecoder<H extends JoseHeader, CS extends JwtClaimSet>
    extends Converter<String, JsonWebToken> {
  final JwtTokenDecoder<H, CS> decoder;
  final JwsValidationContextFactory contextFactory;

  JwtDecoder(this.decoder, this.contextFactory);

  @override
  JsonWebToken convert(String input) => contextFactory != null
      ? decoder(input, validationContext: contextFactory())
      : decoder(input);
}

class JwtEncoder<H extends JoseHeader, CS extends JwtClaimSet>
    extends Converter<JsonWebToken, String> {
  @override
  String convert(JsonWebToken input) => input.encode();
}
