#!/bin/bash

pub global activate test_runner

export PATH="$PATH":"~/.pub-cache/bin"

run_tests -c