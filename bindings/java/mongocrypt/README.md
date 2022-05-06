# mongocrypt Java Wrapper #
The Java wrapper for the companion C library for client side encryption in drivers.

### Testing ###
`./gradlew clean check` runs the java test suite. By default it expects that libmongocrypt is in `./build/jnaLibs/<ARCH>/` - where <ARCH> is the current platform architecture: eg: `linux-x86-64`.

Note: libmongocrypt and the java library are [continuously built on evergreen](https://evergreen.mongodb.com/waterfall/libmongocrypt). Submit patch builds to this evergreen project when making changes to test on supported platforms.

### Publishing ####

First check the build artifacts locally (~/.m2/repository/org/mongodb/mongocrypt): `./gradlew clean downloadJnaLibs publishToMavenLocal`

**Snapshots**

`./gradlew publishSnapshots` 
Will push the latest snapshot version to the sonatype snapshot repository.

**Releases**

`./gradlew publishArchives` 
Will push the latest version to maven central repository. 
Note: Has to be run on a git tagged version / hash. 

### Custom gradle flags ###

* `jnaLibsPath`: Custom local JNA library path for inclusion into the build (rather than downloading from s3)<br>
  Usage: `./gradlew publishSnapshots -DjnaLibsPath=../../../cmake-build-nocrypto`
* `gitRevision`: Sets the Git Revision to download the built resources for from s3.<br>
  Usage: `./gradlew publishSnapshots -DgitRevision=<fullGitHash>`

These flags can be combined with the `downloadJnaLibs` task:
 
* Test without compiling libmongocrypt locally:<br> `./gradlew clean downloadJnaLibs test -DgitRevision=<fullGitHash>`
* Test using a custom libmongocrypt path:<br> `./gradlew clean test -DjnaLibsPath=<path>`


### Debugging errors ###

* Use the info and jna debug flags to output debugging information when running tasks:<br> `./gradlew <taskName> --info -Djna.debug_load=true`
