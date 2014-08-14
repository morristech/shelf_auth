// Copyright (c) 2014, The Shelf Route project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.
library shelf_auth.session.jwt.all.test;

import 'package:unittest/unittest.dart';
import 'jwt_session_test.dart' as jwt_session;
import 'jwt_session_auth_test.dart' as auth;
import 'jwt_session_handler_test.dart' as handler;

main() {
  group('[jwt_session]', jwt_session.main);
  group('[auth]', auth.main);
  group('[handler]', handler.main);
}

