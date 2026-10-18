# Maven fixtures

`commons-lang3.xml` is `org/apache/commons/commons-lang3/maven-metadata.xml`, 27 versions
from 3.0 to 3.21.0, and `plugins.xml` is `org/apache/maven/plugins/maven-metadata.xml`, a
group's plugin prefixes and no `<versioning>`, as repo1.maven.org served them on
2026-10-16.

`global-settings.xml` is the `conf/settings.xml` Apache Maven 3.10.0's binary
distribution ships, with its `maven-default-http-blocker` mirror.

`gradle-versions.json` is four entries of `https://services.gradle.org/versions/all` as it
was served on 2026-10-18, when it listed 532: 9.8.1, 8.14.3, the newest release candidate,
and 5.0-rc-5, one of the 149 with no `wrapperChecksum`.
