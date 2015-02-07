// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisation.sameorigin;

import 'package:shelf/shelf.dart';
import 'dart:async';
import '../authorisation.dart';
import 'package:option/option.dart';

/// An [Authoriser] that denies access to requests where the referer is from a different
/// domain than the request url. This can be used as part of a strategy to guard against
/// XSRF attacks
class SameOriginAuthoriser implements Authoriser {
  Future<bool> isAuthorised(Request request) {
    return new Future.value(new Option(request.headers['referer'])
        .map((refererStr) {
      final referer = Uri.parse(refererStr);
      return referer.host == request.requestedUri.host;
    }).getOrElse(false));
  }
}
