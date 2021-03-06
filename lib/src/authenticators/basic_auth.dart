// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authentication.basic;

import 'dart:async';
import 'dart:convert';

import 'package:http_exception/http_exception.dart';
import 'package:option/option.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_auth/src/context.dart';

import '../authentication.dart';
import '../preconditions.dart';
import '../principal/user_lookup.dart';
import '../util.dart';
import 'core.dart';

const BASIC_AUTH_SCHEME = 'Basic';

/**
 * An [Authenticator] for Basic Authentication (http://tools.ietf.org/html/rfc2617)
 */
class BasicAuthenticator<P extends Principal> extends AbstractAuthenticator<P> {
  final UserLookupByUsernamePassword<P> userLookup;

  BasicAuthenticator(this.userLookup,
      {bool sessionCreationAllowed: false, bool sessionUpdateAllowed: false})
      : super(sessionCreationAllowed, sessionUpdateAllowed) {
    ensure(userLookup, isNotNull);
  }

  @override
  Future<Option<AuthenticatedContext<P>>> authenticate(Request request) {
    final authHeaderOpt = authorizationHeader(request, BASIC_AUTH_SCHEME);
    return authHeaderOpt.map((authHeader) {
      final usernamePasswordStr = _getCredentials(authHeader);

      final usernamePassword = usernamePasswordStr.split(':');

      if (usernamePassword.length != 2) {
        throw new BadRequestException();
      }

      final principalFuture =
          userLookup(usernamePassword[0], usernamePassword[1]);

      return principalFuture.then((principalOption) =>
          principalOption.map((principal) => createContext(principal)));
    }).getOrElse(() => new Future(() => const None()));
  }

  String _getCredentials(AuthorizationHeader authHeader) {
    try {
      return new String.fromCharCodes(
          const Base64Codec.urlSafe().decode(authHeader.credentials));
    } on FormatException catch (_) {
      return '';
    }
  }
}
