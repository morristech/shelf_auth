#!/bin/bash
pushd `dirname $0` > /dev/null
export TEST_DIR=`pwd`
popd > /dev/null
dart --enable-async ${TEST_DIR}/all_tests.dart
