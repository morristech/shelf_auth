library shelf_auth.authentication.core;

import '../authentication.dart';
import '../preconditions.dart';

/**
 * An base class for [Authenticator]s
 */
abstract class AbstractAuthenticator<P extends Principal> extends Authenticator<P> {
  /// true if a session may be established as a result of this authentication
  final bool sessionCreationAllowed;

  /// true if the authentication details may be updated in the session as
  /// a result of this authentication
  final bool sessionUpdateAllowed;

  final bool readsBody;

  AbstractAuthenticator(this.sessionCreationAllowed, this.sessionUpdateAllowed,
      { this.readsBody: false }) {
    ensure(sessionCreationAllowed, isNotNull);
    ensure(sessionUpdateAllowed, isNotNull);
  }

  AuthenticationContext<P> createContext(principal) {
    return new AuthenticationContext(principal,
        sessionCreationAllowed: sessionCreationAllowed,
        sessionUpdateAllowed: sessionUpdateAllowed);
  }

}
