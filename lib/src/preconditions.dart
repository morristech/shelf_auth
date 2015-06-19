// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library preconditions;

import 'package:matcher/matcher.dart';
export 'package:matcher/matcher.dart';

void ensure(value, Matcher matcher, [String failureMessage]) {
  matcher = wrapMatcher(matcher);
  var matchState = {};
  try {
    if (matcher.matches(value, matchState)) return;
  } catch (e, trace) {
    if (failureMessage == null) {
      failureMessage = '${(e is String) ? e : e.toString()} at $trace';
    }
  }
  throw new ArgumentError(_defaultErrorFormatter(
      value, matcher, failureMessage, matchState, false));
}

// copied from test/expect.dart
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
  if (reason != null) description.add(reason).add('\n');
  return description.toString();
}
