// Copyright (c) 2014, The Shelf Auth project authors.
// Please see the AUTHORS file for details.
// All rights reserved. Use of this source code is governed by
// a BSD 2-Clause License that can be found in the LICENSE file.

/// exposes methods to set auth context manually. Useful for other libraries
/// that may have their own way of authenticating that may have nothing to do
/// with shelf or an http request.
/// Also useful for testing to inject auth contexts without having to set up
/// authentication middleware
library shelf_auth.spi;

export 'shelf_auth.dart';
export 'src/zone_context.dart';
