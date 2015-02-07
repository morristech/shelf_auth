// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisation.sameorigin;

import 'package:shelf/shelf.dart';
import 'dart:async';
import '../authorisation.dart';
import 'package:option/option.dart';

class SameOriginAuthoriser implements Authoriser {
  Future<bool> isAuthorised(Request request) {
    return new Future.value(new Option(request.headers['referer'])
        .map((refererStr) {
      final referer = Uri.parse(refererStr);
      print(
          '${referer.authority} == ${request.requestedUri.authority}: ${referer.authority == request.requestedUri.authority}');
      return referer.authority == request.requestedUri.authority;
    }).getOrElse(false));
  }
}
