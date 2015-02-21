// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisation.withexclusions;

import 'package:shelf/shelf.dart';
import 'dart:async';
import '../authorisation.dart';
import 'package:logging/logging.dart';
import '../authentication.dart';

Logger _log = new Logger('shelf_auth.authorisation.withexclusions');

/// An [Authoriser] that delegates to another [Authoriser] unless the request
/// is excluded by [RequestWhitelist]
class AuthoriserWithExclusions implements Authoriser {
  final RequestWhiteList _excluded;
  final Authoriser _realAuthoriser;

  AuthoriserWithExclusions(this._excluded, this._realAuthoriser);

  Future<bool> isAuthorised(Request request) =>
      _excluded != null && _excluded(request)
          ? new Future.value(true)
          : _realAuthoriser.isAuthorised(request);
}
