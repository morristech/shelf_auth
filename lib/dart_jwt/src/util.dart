library jwt.util;

import 'dart:convert';

const Base64Codec _base64 = const Base64Codec.urlSafe();

String bytesToBase64(Iterable<int> bytes, {bool stringPadding: true}) {
  return unpadIfRequired(_base64.encode(bytes), stringPadding: stringPadding);
}

Iterable<int> base64ToBytes(String base64String) =>
    _base64.decode(base64String);

String padIfRequired(String s) {
  final int paddingAmount = s.length % 4;
  return (paddingAmount > 0)
      ? s.padRight(s.length + (4 - paddingAmount), '=')
      : s;
}

String unpadIfRequired(String s, {bool stringPadding: true}) {
  if (!stringPadding || !s.endsWith('=')) {
    return s;
  }
  int cu = '='.codeUnits.first;
  int i = s.length - 1;
  for (; s.codeUnitAt(i) == cu; i--);
  return s.substring(0, i + 1);
}

DateTime decodeIntDate(int secondsSinceEpoch) =>
    new DateTime.fromMillisecondsSinceEpoch(secondsSinceEpoch * 1000);

int encodeIntDate(DateTime dateTime) => dateTime.millisecondsSinceEpoch ~/ 1000;

// TODO: dynamic until dart supports generics on functions
dynamic checkNotNull(dynamic o, [String fieldName = "argument"]) {
  if (o == null) throw new ArgumentError("$fieldName cannot be null");

  return o;
}
