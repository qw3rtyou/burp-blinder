import java.time.Instant
import java.nio.file.Files
import java.nio.file.StandardCopyOption

abstract class EmbedProxyJarTask : DefaultTask() {
    @get:InputFile
    abstract val shadowJarFile: RegularFileProperty

    @get:InputDirectory
    abstract val projectDir: DirectoryProperty

    @get:Inject
    abstract val execOperations: ExecOperations

    @TaskAction
    fun embedJar() {
        // shadowJarFile is the already-published final jar (build/libs/burp-blinder-all.jar).
        val finalJar = shadowJarFile.get().asFile
        val libsDir = projectDir.dir("libs").get().asFile
        val proxyJarFile = File(libsDir, "mcp-proxy-all.jar")

        if (!proxyJarFile.exists()) {
            throw GradleException("Proxy JAR not found at: ${proxyJarFile.absolutePath}")
        }

        // Embed into a private copy, then atomically swap it into place so the watcher only ever
        // sees a complete jar (never the in-progress `jar uf`).
        val embedTmp = File(finalJar.parentFile, ".burp-blinder-all.jar.embed.tmp")
        Files.copy(finalJar.toPath(), embedTmp.toPath(), StandardCopyOption.REPLACE_EXISTING)

        execOperations.exec {
            workingDir(projectDir.get().asFile)
            commandLine("jar", "uf", embedTmp.absolutePath, "-C", libsDir.absolutePath, proxyJarFile.name)
        }

        try {
            Files.move(embedTmp.toPath(), finalJar.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (_: Exception) {
            Files.move(embedTmp.toPath(), finalJar.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
        // Bump mtime after the atomic swap so a file watcher (Burp auto-reload) receives a MODIFY
        // event — an atomic rename alone is often missed by watchers.
        finalJar.setLastModified(System.currentTimeMillis())

        logger.lifecycle("Embedded proxy JAR into ${finalJar.name} (atomic swap)")
    }
}

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktor)
    java
}

group = providers.gradleProperty("group").get()
version = providers.gradleProperty("version").get()
description = providers.gradleProperty("description").get()

dependencies {
    compileOnly(libs.burp.montoya.api)

    implementation(libs.bundles.ktor.server)
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.mcp.kotlin.sdk)

    testImplementation(libs.bundles.test.framework)
    testImplementation(libs.bundles.ktor.test)
    testImplementation(libs.burp.montoya.api)
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(providers.gradleProperty("java.toolchain.version").get().toInt()))
    }
}

kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(providers.gradleProperty("java.toolchain.version").get().toInt()))
    }

    compilerOptions {
        apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_4)
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_4)
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.addAll(
            "-Xjsr305=strict"
        )
    }
}

application {
    mainClass.set("net.portswigger.mcp.ExtensionBase")
}

tasks {
    test {
        useJUnitPlatform()
        systemProperty("file.encoding", "UTF-8")

        testLogging {
            events("passed", "skipped", "failed")
            showExceptions = true
            showCauses = true
            showStackTraces = true
        }
    }

    jar {
        enabled = false
    }

    shadowJar {
        archiveClassifier.set("")
        // Write to a hidden temp, then atomically publish to burp-blinder-all.jar in doLast so the
        // user's auto-reload watcher never sees a half-written jar. Final filename is unchanged.
        archiveFileName.set(".burp-blinder-all.jar.tmp")
        mergeServiceFiles()

        manifest {
            attributes(
                mapOf(
                    "Implementation-Title" to project.name,
                    "Implementation-Version" to project.version,
                    "Implementation-Vendor" to "PortSwigger",
                    "Built-By" to System.getProperty("user.name"),
                    "Built-Date" to Instant.now().toString(),
                    "Built-JDK" to "${System.getProperty("java.version")} (${System.getProperty("java.vendor")} ${
                        System.getProperty("java.vm.version")
                    })",
                    "Created-By" to "Gradle ${gradle.gradleVersion}"
                )
            )
        }


        exclude("META-INF/*.SF")
        exclude("META-INF/*.DSA")
        exclude("META-INF/*.RSA")
        exclude("META-INF/INDEX.LIST")
        exclude("META-INF/DEPENDENCIES")
        exclude("META-INF/NOTICE*")
        exclude("META-INF/LICENSE*")
        exclude("module-info.class")

        duplicatesStrategy = DuplicatesStrategy.EXCLUDE

        // Resolve paths at configuration time (plain File, config-cache safe) so the doLast closure
        // captures no project/script references.
        val tmpJar = layout.buildDirectory.file("libs/.burp-blinder-all.jar.tmp").get().asFile
        val finalJar = layout.buildDirectory.file("libs/burp-blinder-all.jar").get().asFile
        doLast {
            try {
                Files.move(tmpJar.toPath(), finalJar.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: Exception) {
                Files.move(tmpJar.toPath(), finalJar.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
            // Bump mtime after the atomic swap so the auto-reload watcher gets a MODIFY event.
            finalJar.setLastModified(System.currentTimeMillis())
            logger.lifecycle("Published ${finalJar.path} (atomic)")
        }
    }

    register<EmbedProxyJarTask>("embedProxyJar") {
        group = "build"
        description = "Embeds the MCP proxy JAR into the shadow JAR"
        dependsOn(shadowJar)
        // Do not race the test pipeline: make ordering explicit so `./gradlew test embedProxyJar`
        // (and `build`) validate cleanly instead of failing on an implicit task dependency.
        mustRunAfter("test", "compileTestKotlin", "processTestResources")
        // shadowJar publishes the final jar atomically in its doLast; embed operates on that.
        shadowJarFile.set(layout.buildDirectory.file("libs/burp-blinder-all.jar"))
        projectDir.set(layout.projectDirectory)
    }

    build {
        dependsOn(shadowJar)
    }

    withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }
}

tasks.wrapper {
    gradleVersion = "9.2.0"
    distributionType = Wrapper.DistributionType.BIN
}
