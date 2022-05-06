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

repositories {
    mavenCentral()
    google()
}

group = "org.mongodb"
version = "1.5.0-SNAPSHOT"
description = "MongoDB client-side crypto support"

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

val bsonRangeVersion = "[3.10,5.0)"
dependencies {
    api("org.mongodb:bson:$bsonRangeVersion")
    api("net.java.dev.jna:jna:5.11.0")
    implementation("org.slf4j:slf4j-api:1.7.36")

    // Tests
    testImplementation(platform("org.junit:junit-bom:5.8.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("ch.qos.logback:logback-classic:1.2.11")
}

/*
 * Git version information
 */
val gitVersion: String by lazy {
    val describeStdOut = ByteArrayOutputStream()
    exec {
        commandLine = listOf("git", "describe", "--tags", "--always", "--dirty")
        standardOutput = describeStdOut
    }
    val gv: String = describeStdOut.toString().trim()
    gv.subSequence(gv.toCharArray().indexOfFirst { it.isDigit() }, gv.length).toString()
}

val gitHash: String by lazy {
    val describeStdOut = ByteArrayOutputStream()
    exec {
        commandLine = listOf("git", "rev-parse", "HEAD")
        standardOutput = describeStdOut
    }
    describeStdOut.toString().trim()
}

/*
 * Jna copy or download resources
 */
val jnaDownloadsDir = "$buildDir/jnaLibsDownloads/"
val jnaResourcesBuildDir = "$buildDir/jnaLibs/"
val jnaLibsPath: String = System.getProperty("jnaLibsPath", "${jnaResourcesBuildDir}${com.sun.jna.Platform.RESOURCE_PREFIX}")
val jnaResources: String = System.getProperty("jna.library.path", jnaLibsPath)

// Download jnaLibs that match the git to jnaResourcesBuildDir
val revision: String = System.getProperty("gitRevision", if (gitVersion == version) gitVersion else gitHash)
val downloadUrl: String = "https://mciuploads.s3.amazonaws.com/libmongocrypt/java/$revision/libmongocrypt-java.tar.gz"

val jnaMapping: Map<String, String> = mapOf(
    "rhel-62-64-bit" to "linux-x86-64",
    "rhel-67-s390x" to "linux-s390x",
    "ubuntu1604-arm64" to "linux-aarch64",
    "windows-test" to "win32-x86-64",
    "macos_x86_64" to "darwin-x86-64",
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
        path = "${jnaMapping.get(path.substringBefore("/"))}/${name}"
    }
    into(jnaResourcesBuildDir)
    mustRunAfter("downloadJava")
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
        println("jna.library.path contents: ${fileTree(jnaResources).files.joinToString(", ")}")
    }
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
    sourceSets["main"].resources.srcDirs("resources", jnaResourcesBuildDir)
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

tasks.register("publishSnapshots") {
    group = "publishing"
    description = "Publishes snapshots to Sonatype"
    if (version.toString().endsWith("-SNAPSHOT")) {
        dependsOn("downloadJnaLibs")
        dependsOn(tasks.withType<PublishToMavenRepository>())
    }
}

tasks.register("publishArchives") {
    group = "publishing"
    description = "Publishes a release and uploads to Sonatype / Maven Central"

    doFirst {
        if (gitVersion != version) {
            val cause = """
                | Version mismatch:
                | =================
                |
                | $version != $gitVersion
                |
                | The project version does not match the git tag.
                |""".trimMargin()
            throw GradleException(cause)
        } else {
            println("Publishing: ${project.name} : $gitVersion")
        }
    }

    if (gitVersion == version) {
        dependsOn(tasks.withType<PublishToMavenRepository>())
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
