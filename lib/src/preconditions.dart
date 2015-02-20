// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library preconditions;

import 'package:matcher/matcher.dart';
export 'package:matcher/matcher.dart';

const FailureHandler _failureHandler = const _PreconditionFailureHandler();

void ensure(value, Matcher matcher, [String failureMessage]) {
  expect(value, matcher,
      reason: failureMessage, failureHandler: _failureHandler);
}

class _PreconditionFailureHandler implements FailureHandler {
  const _PreconditionFailureHandler();

  void fail(String reason) {
    throw new ArgumentError(reason);
  }

  void failMatch(
      actual, Matcher matcher, String reason, Map matchState, bool verbose) {
    fail(_defaultErrorFormatter(actual, matcher, reason, matchState, verbose));
  }
}

// copied from matcher/expect.dart
String _defaultErrorFormatter(
    actual, Matcher matcher, String reason, Map matchState, bool verbose) {
  var description = new StringDescription();
  description.add('Expected: ').addDescriptionOf(matcher).add('\n');
  description.add('  Actual: ').addDescriptionOf(actual).add('\n');

  var mismatchDescription = new StringDescription();
  matcher.describeMismatch(actual, mismatchDescription, matchState, verbose);

  if (mismatchDescription.length > 0) {
    description.add('   Which: ${mismatchDescription}\n');
  }
  if (reason != null) {
    description.add(reason).add('\n');
  }
  return description.toString();
}
