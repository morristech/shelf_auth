library shelf_auth.authorisers.principal.whitelist;

import 'package:option/option.dart';
import '../preconditions.dart';
import '../authorisation.dart';
import '../authentication.dart';
import '../core.dart';
import 'dart:async';
import 'package:shelf/shelf.dart';

typedef bool PrincipalWhiteList(Principal p);

class PrincipalWhitelistAuthoriser implements Authoriser {
  final PrincipalWhiteList whitelist;
  final bool denyUnauthenticated;

  PrincipalWhitelistAuthoriser(this.whitelist,
      {this.denyUnauthenticated: false}) {
    ensure(whitelist, isNotNull);
    ensure(denyUnauthenticated, isNotNull);
  }

  Future<bool> isAuthorised(Request request) =>
      new Future.value(_isAuthorised(request));

  bool _isAuthorised(Request request) {
    final authContextOpt = getAuthenticatedContext(request);
    if (authContextOpt is None) {
      return !denyUnauthenticated;
    } else {
      final isWhitelistedOpt =
          authContextOpt.map((context) => whitelist(context.principal));

      return isWhitelistedOpt.getOrElse(false);
    }
  }
}
