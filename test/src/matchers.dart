// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library test.matcher;

import 'package:matcher/matcher.dart';
import 'package:shelf/shelf.dart';

typedef Getter(object);

Matcher requestWithUrlPath(matcher) =>
    requestMatcher("url.path", matcher, (Request request) => request.url.path);

Matcher requestWithUrl(matcher) =>
    requestMatcher("url", matcher, (Request request) => request.url);

Matcher requestWithScriptName(matcher) => requestMatcher(
    "scriptName", matcher, (Request request) => request.scriptName);

Matcher requestWithHeaderValue(String headerName, matcher) => requestMatcher(
    "headers", matcher, (Request request) => request.headers[headerName]);

Matcher requestWithContextValue(String contextParamName, matcher) =>
    requestMatcher("context", matcher,
        (Request request) => request.context[contextParamName]);

Matcher requestMatcher(String fieldName, matcher, Getter getter) =>
    fieldMatcher("Request", fieldName, matcher, getter);

Matcher fieldMatcher(
    String className, String fieldName, matcher, Getter getter) =>
        new FieldMatcher(className, fieldName, matcher, getter);

class FieldMatcher extends CustomMatcher {
  final Getter getter;

  FieldMatcher(String className, String fieldName, matcher, this.getter)
      : super("$className with $fieldName that", fieldName, matcher);

  featureValueOf(actual) => getter(actual);
}

class CaptureMatcher extends Matcher {
  get last => _last;
  var _last;

  @override
  Description describe(Description description) {
    return description;
  }

  @override
  bool matches(item, Map matchState) {
    _last = item;
    return true;
  }
}
