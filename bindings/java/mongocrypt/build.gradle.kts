/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

import de.undercouch.gradle.tasks.download.Download
import java.io.ByteArrayOutputStream
import java.net.URI

buildscript {
    repositories {
        mavenCentral()
        google()
    }
    dependencies {
        "classpath"(group = "net.java.dev.jna", name = "jna", version = "5.11.0")
    }
}

plugins {
    `java-library`
    `maven-publish`
    signing
    id("de.undercouch.download") version "5.0.5"
    id("biz.aQute.bnd.builder") version "6.2.0"
}

allprojects {
    repositories {
        mavenCentral()
        google()
    }
}

group = "org.mongodb"
version = "1.8.0-SNAPSHOT"
description = "MongoDB client-side crypto support"

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8

    registerFeature("loggingSupport") {
        usingSourceSet(sourceSets["main"])
    }
}


val bsonRangeVersion = "[3.10,5.0)"
dependencies {
    api("org.mongodb:bson:$bsonRangeVersion")
    api("net.java.dev.jna:jna:5.11.0")
    "loggingSupportImplementation"("org.slf4j:slf4j-api:1.7.36")

    // Tests
    testImplementation(platform("org.junit:junit-bom:5.8.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("ch.qos.logback:logback-classic:1.2.11")
}

/*
 * Git version information
 */

// Returns a String representing the output of `git describe`
val gitDescribe by lazy {
    val describeStdOut = ByteArrayOutputStream()
    exec {
        commandLine = listOf("git", "describe", "--tags", "--always", "--dirty")
        standardOutput = describeStdOut
    }
    describeStdOut.toString().trim()
}

val isJavaTag by lazy { gitDescribe.startsWith("java") }
val gitVersion by lazy { gitDescribe.subSequence(gitDescribe.toCharArray().indexOfFirst { it.isDigit() }, gitDescribe.length).toString() }

val defaultDownloadRevision: String by lazy {
    val gitCommandLine = if (gitVersion == version) {
        listOf("git", "rev-list", "-n", "1", gitVersion)
    } else {
        listOf("git", "rev-parse", "HEAD")
    }
    val describeStdOut = ByteArrayOutputStream()
    exec {
        commandLine = gitCommandLine
        standardOutput = describeStdOut
    }
    describeStdOut.toString().trim()
}

/*
 * Jna copy or download resources
 */
val jnaDownloadsDir = "$buildDir/jnaLibs/downloads/"
val jnaResourcesDir = "$buildDir/jnaLibs/resources/"
val jnaLibPlatform: String = if (com.sun.jna.Platform.RESOURCE_PREFIX.startsWith("darwin")) "darwin" else com.sun.jna.Platform.RESOURCE_PREFIX
val jnaLibsPath: String = System.getProperty("jnaLibsPath", "${jnaResourcesDir}${jnaLibPlatform}")
val jnaResources: String = System.getProperty("jna.library.path", jnaLibsPath)

// Download jnaLibs that match the git to jnaResourcesBuildDir
val downloadRevision: String = System.getProperties().computeIfAbsent("gitRevision") { k -> defaultDownloadRevision }.toString()
val downloadUrl: String = "https://mciuploads.s3.amazonaws.com/libmongocrypt/java/$downloadRevision/libmongocrypt-java.tar.gz"

val jnaMapping: Map<String, String> = mapOf(
    "rhel-62-64-bit" to "linux-x86-64",
    "rhel72-zseries-test" to "linux-s390x",
    "rhel-71-ppc64el" to "linux-ppc64le",
    "ubuntu1604-arm64" to "linux-aarch64",
    "windows-test" to "win32-x86-64",
    "macos" to "darwin"
)

tasks.register<Download>("downloadJava") {
    src(downloadUrl)
    dest("${jnaDownloadsDir}/libmongocrypt-java.tar.gz")
    overwrite(true)
}

tasks.register<Copy>("unzipJava") {
    outputs.upToDateWhen { false }
    from(tarTree(resources.gzip("${jnaDownloadsDir}/libmongocrypt-java.tar.gz")))
    include(jnaMapping.keys.flatMap {
        listOf("${it}/nocrypto/**/libmongocrypt.so", "${it}/nocrypto/**/libmongocrypt.dylib", "${it}/nocrypto/**/mongocrypt.dll" )
    })
    eachFile {
        path = "${jnaMapping[path.substringBefore("/")]}/${name}"
    }
    into(jnaResourcesDir)
    mustRunAfter("downloadJava")

    doLast {
        println("jna.library.path contents: \n  ${fileTree(jnaResourcesDir).files.joinToString(",\n  ")}")
    }
}

tasks.register("downloadJnaLibs") {
    dependsOn("downloadJava", "unzipJava")
}

tasks.test {
    systemProperty("jna.debug_load", "true")
    systemProperty("jna.library.path", jnaResources)
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }

    doFirst {
        println("jna.library.path contents:")
        println(fileTree(jnaResources)  {
            this.setIncludes(listOf("*.*"))
        }.files.joinToString(",\n  ", "  "))
    }
    mustRunAfter("downloadJnaLibs", "downloadJava", "unzipJava")
}

tasks.withType<AbstractPublishToMaven> {
    description = """$description
        | System properties:
        | =================
        |
        | jnaLibsPath    : Custom local JNA library path for inclusion into the build (rather than downloading from s3)
        | gitRevision    : Optional Git Revision to download the built resources for from s3.
    """.trimMargin()
}

tasks.withType<PublishToMavenRepository> {
    sourceSets["main"].resources.srcDirs("resources", jnaResourcesDir)
}

/*
 * Publishing
 */
tasks.register<Jar>("sourcesJar") {
    description = "Create the sources jar"
    from(sourceSets.main.get().allJava)
    archiveClassifier.set("sources")
}

tasks.register<Jar>("javadocJar") {
    description = "Create the Javadoc jar"
    from(tasks.javadoc)
    archiveClassifier.set("javadoc")
}

tasks.jar {
    manifest {
        attributes(
                "-exportcontents" to "com.mongodb.crypt.capi.*;-noimport:=true",
                "Automatic-Module-Name" to "com.mongodb.crypt.capi",
                "Import-Package" to """org.bson.*;version="$bsonRangeVersion"""",
                "Build-Version" to gitVersion,
                "Bundle-Version" to gitVersion,
                "Bundle-Name" to "MongoCrypt",
                "Bundle-SymbolicName" to "com.mongodb.crypt.capi",
                "Private-Package" to ""
        )
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            artifactId = "mongodb-crypt"
            from(components["java"])
            suppressPomMetadataWarningsFor("loggingSupportApiElements")
            suppressPomMetadataWarningsFor("loggingSupportRuntimeElements")

            artifact(tasks["sourcesJar"])
            artifact(tasks["javadocJar"])

            pom {
                name.set("MongoCrypt")
                description.set(project.description)
                url.set("http://www.mongodb.org")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("Various")
                        organization.set("MongoDB")
                    }
                }
                scm {
                    url.set("https://github.com/mongodb/libmongocrypt")
                    connection.set("scm:https://github.com/mongodb/libmongocrypt")
                    developerConnection.set("scm:git@github.com:mongodb/libmongocrypt")
                }
            }
        }
    }

    repositories {
        maven {
            val snapshotsRepoUrl = URI("https://oss.sonatype.org/content/repositories/snapshots/")
            val releasesRepoUrl = URI("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
            credentials {
                val nexusUsername: String? by project
                val nexusPassword: String? by project
                username = nexusUsername ?: ""
                password = nexusPassword ?: ""
            }
        }
    }
}

signing {
    sign(publishing.publications["mavenJava"])
}

tasks.javadoc {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}

tasks.register("publishToSonatype") {
    group = "publishing"
    description = """Publishes to Sonatype.
        |
        | - If the version string ends with SNAPSHOT then publishes to the Snapshots repo.
        |   Note: Uses the JNA libs from the current build.
        |
        | - If is a release then publishes the release to maven central staging.
        |   A release is when the current git tag is prefixed with java (eg: java-1.7.0)
        |   AND the git tag version matches the version the build.gradle.kts.
        |   Note: Uses the JNA libs from the associated tag.
        |   Eg: Tag java-1.7.0 will use the JNA libs created by the 1.7.0 release tag.
        |
        | To override the JNA library downloaded use -DgitRevision=<git hash>
    """.trimMargin()
    val isSnapshot = version.toString().endsWith("-SNAPSHOT")
    val isRelease = isSnapshot || (isJavaTag && gitVersion == version)

    doFirst {
        if (isSnapshot && isJavaTag) {
                throw GradleException("""
                | Invalid Release
                | ===============
                |
                | Version: $version 
                | GitVersion: $gitVersion
                | isJavaTag: $isJavaTag
                |
                |""".trimMargin())
        }

        if (isRelease) {
            println("Publishing: ${project.name} : $gitVersion")
        } else {
            println("""
                | Not a Java release:
                |
                | Version:
                | ========
                |
                | $gitDescribe
                |
                | The project version does not match the git tag.
                |""".trimMargin())
        }
    }

    if (isRelease) {
        dependsOn("downloadJnaLibs")
        finalizedBy(tasks.withType<PublishToMavenRepository>())
        tasks.withType<PublishToMavenRepository>().forEach { t -> t.mustRunAfter("downloadJnaLibs", "downloadJava", "unzipJava") }
    }
}


/*
For security we allow the signing-related project properties to be passed in as environment variables, which
Gradle enables if they are prefixed with "ORG_GRADLE_PROJECT_".  But since environment variables can not contain
the '.' character and the signing-related properties contain '.', here we map signing-related project properties with '_'
to ones with '.' that are expected by the signing plugin.
*/
gradle.taskGraph.whenReady {
    if (allTasks.any { it is Sign }) {
        val signing_keyId: String? by project
        val signing_secretKeyRingFile: String? by project
        val signing_password: String? by project

        allprojects {
            signing_keyId?.let { extra["signing.keyId"] = it }
            signing_secretKeyRingFile?.let { extra["signing.secretKeyRingFile"] = it }
            signing_password?.let { extra["signing.password"] = it }
        }
    }
}
