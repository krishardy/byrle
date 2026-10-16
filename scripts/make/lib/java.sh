#!/usr/bin/env bash
# The JDK and Maven releases `make install-java` installs, with each tarball's checksum as
# the release lists it. Sourced, not executed.
# shellcheck disable=SC2034  # read by the scripts that source this

# Eclipse Temurin, from github.com/adoptium/temurin21-binaries.
jdk_release="jdk-21.0.12.1+1"
jdk_file_version="21.0.12.1_1"
jdk_sha256_x64="ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94"
jdk_sha256_aarch64="23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223"

# Apache Maven, from dlcdn.apache.org.
maven_version="3.10.0"
maven_sha512="908b1501bfb420bf7c8affb855534a9c407fd6099367bfb9f2f2dcb8e9799102bffb84518cde74c679bd76870247c6528683abdd620581bffa90f95d92d175aa"
