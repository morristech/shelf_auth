// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf.util;

import 'dart:async';
import 'dart:io';

import 'package:stack_trace/stack_trace.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_exception_response/exception.dart';
import 'package:option/option.dart';
import 'core.dart';

/// Like [new Future], but avoids around issue 11911 by using [new Future.value]
/// under the covers.
Future newFuture(callback()) => new Future.value().then((_) => callback());

/// Like [Future.sync], but wraps the Future in [Chain.track] as well.
Future syncFuture(callback()) => Chain.track(new Future.sync(callback));

/// Run [callback] and capture any errors that would otherwise be top-leveled.
///
/// If [this] is called in a non-root error zone, it will just run [callback]
/// and return the result. Otherwise, it will capture any errors using
/// [runZoned] and pass them to [onError].
catchTopLevelErrors(callback(), void onError(error, StackTrace stackTrace)) {
  if (Zone.current.inSameErrorZone(Zone.ROOT)) {
    return runZoned(callback, onError: onError);
  } else {
    return callback();
  }
}

/// Returns a [Map] with the values from [original] and the values from
/// [updates].
///
/// For keys that are the same between [original] and [updates], the value in
/// [updates] is used.
///
/// If [updates] is `null` or empty, [original] is returned unchanged.
Map updateMap(Map original, Map updates) {
  if (updates == null || updates.isEmpty) return original;

  return new Map.from(original)..addAll(updates);
}

Option<AuthorizationHeader> authorizationHeader(
    Request request, String authScheme) {
  return new Option(authorizationHeaders(request).firstWhere(
      (authHeader) => authHeader.authScheme == authScheme, orElse: () => null));
}

Iterable<AuthorizationHeader> authorizationHeaders(Request request) {
  List<String> authHeaders = _authHeaders(request);

  return authHeaders.map((header) {
    final List<String> parts = header.split(' ');
    if (parts.length != 2) {
      throw new BadRequestException();
    }
    return new AuthorizationHeader(parts[0], parts[1]);
  });
}

Response addAuthorizationHeader(
    Response response, AuthorizationHeader authorizationHeader) {
  final String credentials = '${authorizationHeader.authScheme} '
      '${authorizationHeader.credentials}';

  List<String> authHeaders = _authHeaders(response);

  final newAuthHeaders = []
    ..addAll(authHeaders)
    ..add(credentials);
  final newAuthHeadersStr = newAuthHeaders.join(',');

  return response.change(
      headers: {HttpHeaders.AUTHORIZATION: newAuthHeadersStr});
}

// TODO: raise issue on shelf to expose the Message class
List<String> _authHeaders(message) {
  final authHeadersString = message.headers[HttpHeaders.AUTHORIZATION];
  return authHeadersString == null ? [] : authHeadersString.split(',');
}

class AuthorizationHeader {
  final String authScheme;
  final String credentials;

  AuthorizationHeader(this.authScheme, this.credentials);
}

Middleware withOptionalExclusions(
        Middleware middleware, RequestWhiteList excluded) =>
    excluded != null ? withExclusions(middleware, excluded) : middleware;

Middleware withExclusions(Middleware middleware, RequestWhiteList excluded) {
  return (Handler innerHandler) {
    return _wrappedHandler(innerHandler, middleware, excluded);
  };
}

Handler _wrappedHandler(
    Handler innerHandler, Middleware middleware, RequestWhiteList excluded) {
  return (Request request) {
    if (excluded(request)) {
      return innerHandler(request);
    } else {
      return middleware(innerHandler)(request);
    }
  };
}
