library shelf_auth.session.jwt.handler;

import 'jwt_session.dart';
import '../../authentication.dart';
import 'package:shelf/shelf.dart';

class JwtSessionHandler implements SessionHandler {

  @override
  Response handle(AuthenticationContext context, Request request, Response response) {
    // TODO: implement handle
  }
}