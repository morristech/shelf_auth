// Copyright (c) 2014, The Shelf Route project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.
library constrain.all.test;

import 'package:unittest/unittest.dart';
import 'shelf_auth_test.dart' as core;
import 'authenticators/basic_auth_test.dart' as basic;


main() {
  group('[core]', core.main);
  group('[basic]', basic.main);
}

