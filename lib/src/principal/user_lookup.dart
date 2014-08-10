library shelf_auth.principal.lookup;

import '../authentication.dart';
import 'dart:async';
import 'package:option/option.dart';

typedef Future<Option<P>> UserLookupByUsernamePassword<P extends Principal>(
    String username, String password);

typedef Future<Option<P>> UserLookupByUsername<P extends Principal>(
    String username);
