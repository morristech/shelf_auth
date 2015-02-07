// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authentication.usernamepassword;

import '../authentication.dart';
import 'package:shelf/shelf.dart';
import 'dart:async';
import 'package:option/option.dart';
import '../principal/user_lookup.dart';
import 'package:shelf_exception_response/exception.dart';
import '../preconditions.dart';
import 'core.dart';
import 'package:shelf_path/shelf_path.dart';
import 'dart:io';
import '../util.dart';

const String SHELF_AUTH_STD_USER_CREDENTIALS =
    'shelf_auth.std.user.credentials';

StdUserCredentials getStdUserCredentials(Request request) =>
    getPathParameter(request, SHELF_AUTH_STD_USER_CREDENTIALS);

Request setStdUserCredentials(
    Request request, StdUserCredentials credentials) => addPathParameters(
        request, {SHELF_AUTH_STD_USER_CREDENTIALS: credentials});

class StdUserCredentials {
  final String username;
  final String password;

  StdUserCredentials(this.username, this.password);

  StdUserCredentials.build({this.username, this.password});

  StdUserCredentials.fromJson(Map json)
      : username = json['username'],
        password = json['password'];
}

/**
 * An [Authenticator] for standard username password form style login.
 * There are two ways to use this
 *
 * 1. submit a `application/x-www-form-urlencoded` encoded body where the
 * username and password form fields must be called `username` and `password`
 * respectively.
 * 1. add Middleware before the authenicator that extracts the username and
 * password from the request (somehow) and use the `setStdUserCredentials`
 * to add them to the context
 *
 * Note: this authenticator is intended for dedicated login routes. It behaves
 * differently to other authenticators as it treats missing credentials the
 * same as invalid credentials and throws in both cases. It also reads the body
 * and passes a request on to the innerHandler which has no body
 */
class UsernamePasswordAuthenticator<P extends Principal>
    extends AbstractAuthenticator<P> {
  final UserLookupByUsernamePassword<P> userLookup;

  UsernamePasswordAuthenticator(this.userLookup,
      {bool sessionCreationAllowed: true, bool sessionUpdateAllowed: true})
      : super(sessionCreationAllowed, sessionUpdateAllowed, readsBody: true) {
    ensure(userLookup, isNotNull);
  }

  @override
  Future<Option<AuthenticatedContext<P>>> authenticate(Request request) {
    final credentialsFuture = _extractCredentials(request);

    final principalFuture = credentialsFuture.then((credentials) =>
        userLookup(credentials.username, credentials.password));

    return principalFuture.then((principalOption) => principalOption
        .map((principal) => createContext(principal))
        .orElse(() => throw new UnauthorizedException()));
  }

  Future<StdUserCredentials> _extractCredentials(Request request) {
    final contextCredentials = getStdUserCredentials(request);
    final credentialsFuture = syncFuture(() => contextCredentials != null
        ? contextCredentials
        : _extractFormCredentials(request));

    return credentialsFuture.then((credentials) {
      if (credentials == null || credentials.username == null) {
        throw new UnauthorizedException();
      }

      return credentials;
    });
  }

  Future<StdUserCredentials> _extractFormCredentials(Request request) {
    final contentTypeStr = request.headers[HttpHeaders.CONTENT_TYPE];
    if (contentTypeStr != null) {
      final contentType = ContentType.parse(contentTypeStr);

      if (contentType.mimeType == "application/x-www-form-urlencoded") {
        return request.readAsString().then(
            (s) => new StdUserCredentials.fromJson(Uri.splitQueryString(s)));
      }
    }

    return new Future.value(null);
  }
}
