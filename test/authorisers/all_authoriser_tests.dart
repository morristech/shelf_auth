// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.authorisers.all.test;

import 'package:unittest/unittest.dart';
import 'authorisation_test.dart' as authorisation;
import 'same_origin_authoriser_test.dart' as same_origin;
import 'principal_whitelist_authoriser_test.dart' as principal_whitelist;

main() {
  group('[authorisation]', authorisation.main);
  group('[same_origin]', same_origin.main);
  group('[principal_whitelist]', principal_whitelist.main);
}
