library shelf_auth.session.jwt.handler;

import 'jwt_session.dart';
import '../../authentication.dart';
import 'package:shelf/shelf.dart';
import '../../preconditions.dart';
import '../../util.dart';

class JwtSessionHandler implements SessionHandler {
  final String issuer;
  final String secret;
  final Duration idleTimeout;
  final Duration totalSessionTimeout;

  JwtSessionHandler(this.issuer, this.secret, this.idleTimeout,
      this.totalSessionTimeout) {
    ensure(issuer, isNotNull);
    ensure(secret, isNotNull);
    ensure(idleTimeout, isNotNull);
  }

  @override
  Response handle(AuthenticationContext context, Request request,
                  Response response) {
    final now = new DateTime.now();

    final sessionContext = _getSessionContext(context);
    final noSessionRenewalAfter = sessionContext.noSessionRenewalAfter;

    if (noSessionRenewalAfter.isAfter(now)) {
      return response;
    }

    final remainingSessionTime = noSessionRenewalAfter.difference(now);

    final newIdleTimeout = idleTimeout <= remainingSessionTime ?
        idleTimeout : remainingSessionTime;

    final sessionToken = createSessionToken(secret, issuer,
        context.principal.name, idleTimeout: newIdleTimeout,
        totalSessionTimeout: remainingSessionTime);

    return addAuthorizationHeader(response,
        new AuthorizationHeader(JWT_SESSION_AUTH_SCHEME, sessionToken));
  }

  SessionAuthenticationContext _getSessionContext(AuthenticationContext context) {
    final now = new DateTime.now();

    return context is SessionAuthenticationContext ? context :
      new SessionAuthenticationContext(context.principal, now, now,
          now.add(totalSessionTimeout));
  }
}