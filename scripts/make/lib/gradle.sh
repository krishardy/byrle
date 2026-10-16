#!/usr/bin/env bash
# The Gradle release `make install-gradle` installs, with its distribution's sha256 as
# services.gradle.org/versions lists it. Sourced, not executed.
# shellcheck disable=SC2034  # read by the scripts that source this

gradle_version="9.8.1"
gradle_sha256="dce76f55f8e251a3a1f130eb120f30b3d271de2b76c9b0729d316b5a1b6dc01f"
