// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisation.builder;

import 'package:shelf/shelf.dart';
import 'package:logging/logging.dart';
import 'authorisation.dart';
import 'authorisers/same_origin_authoriser.dart';
import 'authorisers/principal_whitelist_authoriser.dart';

export 'core.dart';

final Logger _log = new Logger('shelf_auth.authorisation.builder');

/// Creates a builder to help with the creation of shelf_auth authorisation middleware.
///
/// For example
///
///     var authorisationMiddleware = (authorisationBuilder()
///        .sameOrigin()
///        .principalWhitelist((p) => p.name == 'fred')
///      .build();
///
AuthorisationBuilder authorisationBuilder() => new AuthorisationBuilder();

/// A builder to help with the creation of shelf_auth middleware
class AuthorisationBuilder {
  List<Authoriser> _authorisers = [];

  /// adds a [SameOriginAuthoriser] to the list of authorisers
  AuthorisationBuilder sameOrigin() => authoriser(new SameOriginAuthoriser());

  /// adds a [PrincipalWhitelistAuthoriser] to the list of authorisers
  AuthorisationBuilder principalWhitelist(PrincipalWhiteList whitelist,
      {bool denyUnauthenticated: false}) => authoriser(
          new PrincipalWhitelistAuthoriser(whitelist,
              denyUnauthenticated: denyUnauthenticated));

  /// adds the given authoriser to the list of authorisers
  AuthorisationBuilder authoriser(Authoriser authoriser) {
    _authorisers.add(authoriser);
    return this;
  }

  /// Creates middleware from the provided details
  Middleware build() => authorise(_authorisers);
}
