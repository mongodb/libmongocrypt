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

import java.io.ByteArrayOutputStream
import java.net.URI
import de.undercouch.gradle.tasks.download.Download
import org.gradle.internal.SystemProperties


buildscript {
    repositories {
        jcenter()
        mavenCentral()
    }
}

plugins {
    `java-library`
    `maven-publish`
    signing
    id("de.undercouch.download").version("3.4.3")
}

repositories {
    google()
    jcenter()
}

group = "org.mongodb"
version = "1.0.0-SNAPSHOT"
description = "MongoDB client-side crypto support"

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}


dependencies {
    api("org.mongodb:bson:3.10.1")   // TODO: what version to depend on?
    api("net.java.dev.jna:jna:4.5.2")
    implementation("org.slf4j:slf4j-api:1.7.6")

    // Tests
    testImplementation("junit:junit:4.12")
    testRuntime("ch.qos.logback:logback-classic:1.1.1")
}

/*
 * Publishing
 */
tasks.register<Jar>("sourcesJar") {
    description = "Create the sources jar"
    from(sourceSets.main.get().allSource)
    archiveClassifier.set("sources")
}

tasks.register<Jar>("javadocJar") {
    description = "Create the Javadoc jar"
    from(tasks.javadoc)
    archiveClassifier.set("javadoc")
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            artifactId = "mongo-crypt"
            from(components["java"])
            artifact(tasks["sourcesJar"])
            artifact(tasks["javadocJar"])
            versionMapping {
                usage("java-api") {
                    fromResolutionOf("runtimeClasspath")
                }
                usage("java-runtime") {
                    fromResolutionResult()
                }
            }
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
        dependsOn(tasks.withType<PublishToMavenRepository>())
    }
}

val gitVersion: String by lazy {
    val describeStdOut = ByteArrayOutputStream()
    exec {
        commandLine = listOf("git", "describe", "--tags", "--always", "--dirty")
        standardOutput = describeStdOut
    }
    describeStdOut.toString().substring(1).trim()
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
 * jnaLibs check - before all publishing tasks
 */
val jnaLibsPath = System.getProperty("jnaLibsPath", "")
tasks.withType<AbstractPublishToMaven> {
    if (!System.getProperties().containsKey("jnaLibsNoCheck")) {
        doFirst {
            if (jnaLibsPath.isEmpty()) {
                val cause = """
                |
                | No Jna Libs:
                | ============
                |
                | Missing Jna Libs - pubishing would not include any libs!
                |
                | Please include -DjnaLibsPath=<path-to-libs> when running a publish command.
                |""".trimMargin()
                throw GradleException(cause)
            } else {
                println("\n\nPlease confirm the jnaLibs resources layout: (Use -DjnaLibsNoCheck to bypass)\n")
                File(jnaLibsPath).walkTopDown().forEach { println(" - ${it.toString().removePrefix(jnaLibsPath)}") }
                println("--------------------------------------------")
                println("Is the above the expected layout? [y/n?]\n\n")
                if (readLine()!!.trim().toLowerCase() != "y") {
                    throw GradleException("Cancelling...")
                }
            }
        }
    }

    if (jnaLibsPath.isNotEmpty()) {
        sourceSets["main"].resources.srcDirs("resources", jnaLibsPath)
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

tasks.withType<Test> {
    @Suppress("UNCHECKED_CAST")
    systemProperties((System.getProperties().toMap() as Map<String, Any>).filter { it.key.startsWith("jna.") })
}

/*
 * Jna Libs - temporary testing helpers
 */
// No jnaLibs so download the latest only add to test resource
if (jnaLibsPath.isEmpty() && System.getProperty("jna.libary.path", "").isEmpty()) {

    // TODO - Any more libraries? Check the `{OS}-{ARCH}` is correct
    val jnaLibs = mapOf(
            "https://s3.amazonaws.com/mciuploads/libmongocrypt/ubuntu1604/latest/libmongocrypt.tar.gz" to "linux-x86-64",
            "https://s3.amazonaws.com/mciuploads/libmongocrypt/windows-test/latest/libmongocrypt.tar.gz" to "win32-x86-64",
            "https://s3.amazonaws.com//mciuploads/libmongocrypt/macos/latest/libmongocrypt.tar.gz" to "darwin")

    val downloadJnaLibs by tasks.register<DefaultTask>("downloadJnaLibs")
    jnaLibs.forEach { k, v ->
        tasks {
            val download by register<Download>("download-$v") {
                src(k)
                dest("$buildDir/jnaLibsDownloads/$v.tgz")
                overwrite(false)
            }

            val unzip by register<Copy>("unzip-$v") {
                from(tarTree(resources.gzip("$buildDir/jnaLibsDownloads/$v.tgz")))
                include("**/libmongocrypt.so", "**/libmongocrypt.dll", "**/libmongocrypt.dylib")
                eachFile {
                    path = name
                }
                into("$buildDir/jnaLibs/$v/")
            }
            unzip.dependsOn(download)
            downloadJnaLibs.dependsOn(unzip)
        }
    }

    tasks.withType<Test> {
        dependsOn(downloadJnaLibs)
        sourceSets["test"].resources.srcDirs("resources", "$buildDir/jnaLibs")
    }
}
