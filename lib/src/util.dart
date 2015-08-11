// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf.util;

import 'dart:async';
import 'dart:io';

import 'package:shelf/shelf.dart';
import 'package:http_exception/http_exception.dart';
import 'package:option/option.dart';
import 'core.dart';
import 'package:quiver/iterables.dart';

/// Like [new Future], but avoids around issue 11911 by using [new Future.value]
/// under the covers.
Future newFuture(callback()) => new Future.value().then((_) => callback());

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

Request removeAuthorizationHeader(Request request, String authScheme) {
  final authHeaders = authorizationHeaders(request);
  if (authHeaders.isEmpty) {
    return request;
  }
  final adjustedAuthHeaders = authHeaders
      .where((authHeader) => authHeader.authScheme != authScheme)
      .map((ah) => ah.toString());
  if (adjustedAuthHeaders.length == authHeaders.length) {
    return request;
  } else {
    final r = request;

    final adjustedHeaders = {}
      ..addAll(r.headers)
      ..remove(HttpHeaders.AUTHORIZATION);
    if (adjustedAuthHeaders.isNotEmpty) {
      final adjustedAuthHeadersStr =
          adjustedAuthHeaders.map((h) => h.toString()).join(',');
      adjustedHeaders[HttpHeaders.AUTHORIZATION] = adjustedAuthHeadersStr;
    }

    return new Request(r.method, r.requestedUri,
        handlerPath: r.handlerPath,
        url: r.url,
        protocolVersion: r.protocolVersion,
        body: r.read(),
        context: r.context,
        encoding: r.encoding,
        headers: adjustedHeaders);
  }
}

Option<AuthorizationHeader> responseAuthorizationHeader(
    Response response, String authScheme) {
  return new Option(responseAuthorizationHeaders(response).firstWhere(
      (authHeader) => authHeader.authScheme == authScheme, orElse: () => null));
}

Iterable<AuthorizationHeader> authorizationHeaders(Request request) =>
    _authorizationHeaders(request);

Iterable<AuthorizationHeader> responseAuthorizationHeaders(Response response) =>
    _authorizationHeaders(response);

Iterable<AuthorizationHeader> _authorizationHeaders(message) {
  List<String> authHeaders = _authHeaders(message);

  return authHeaders.map((header) {
    final List<String> parts = header.split(' ');
    if (parts.length != 2) {
      throw new BadRequestException();
    }
    return new AuthorizationHeader(parts[0], parts[1]);
  });
}

Response addAuthorizationHeader(
    Response response, AuthorizationHeader authorizationHeader,
    {bool omitIfAuthSchemeAlreadyInHeader: true}) {
  final Iterable<AuthorizationHeader> authHeaders =
      _authorizationHeaders(response);

  if (omitIfAuthSchemeAlreadyInHeader &&
      authHeaders.any((authHeader) =>
          authHeader.authScheme == authorizationHeader.authScheme)) {
    return response;
  } else {
    final Iterable<AuthorizationHeader> newAuthHeaders =
        concat([authHeaders, [authorizationHeader]]);

    final newAuthHeadersStr = newAuthHeaders.map((h) => h.toString()).join(',');

    return response.change(
        headers: {HttpHeaders.AUTHORIZATION: newAuthHeadersStr});
  }
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

  String toString() => '${authScheme} ${credentials}';

  Map toAuthorizationHeader() => { HttpHeaders.AUTHORIZATION: toString() };
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
