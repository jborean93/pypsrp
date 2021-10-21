#!/bin/bash -ex

source ./build_helpers/lib.sh

lib::setup::system_requirements
lib::setup::python_requirements
lib::sanity::run
lib::tests::run
