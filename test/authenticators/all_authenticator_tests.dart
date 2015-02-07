// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authenticators.all.test;

import 'package:unittest/unittest.dart';
import 'basic_auth_test.dart' as basic;
import 'username_password_auth_test.dart' as username_password;

main() {
  group('[basic]', basic.main);
  group('[username_password]', username_password.main);
}
