// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

library shelf_auth.principal.lookup;

import '../authentication.dart';
import 'dart:async';
import 'package:option/option.dart';

typedef Future<Option<P>> UserLookupByUsernamePassword<P extends Principal>(
    String username, String password);

typedef Future<Option<P>> UserLookupByUsername<P extends Principal>(
    String username);
