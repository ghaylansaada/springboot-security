import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.2.10"
    `maven-publish`
    `java-library`
}

group = "io.ghaylan.springboot"
version = "1.0.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
    mavenLocal()
}

dependencies {
    implementation("org.springframework:spring-webflux:6.2.10")
    api("org.springframework.security:spring-security-web:6.5.3")
    api("org.springframework.security:spring-security-config:6.5.3")
    implementation("org.springframework.boot:spring-boot-autoconfigure:3.5.5")
    implementation("org.springframework.boot:spring-boot-starter-data-redis-reactive:3.5.5")

    implementation("io.jsonwebtoken:jjwt-api:0.13.0")
    implementation("io.jsonwebtoken:jjwt-impl:0.13.0")
    implementation("io.jsonwebtoken:jjwt-jackson:0.13.0")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor:1.10.2")
}

kotlin {
    compilerOptions {
        javaParameters = true
        jvmTarget.set(JvmTarget.JVM_21)
        freeCompilerArgs.addAll(
            "-Xjsr305=strict",                       // strict nullability interop
            "-java-parameters",                      // keep param names for Spring
            "-Xjvm-default=all",                     // faster, cleaner proxies
            "-Xemit-jvm-type-annotations",           // better interop for frameworks
            "-opt-in=kotlin.RequiresOptIn",          // allow experimental APIs
            "-Xstring-concat=indy-with-constants",   // best string concat on JDK 21
            "-Xannotation-default-target=param-property")
    }
}

java {
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<Test> {
    useJUnitPlatform()
}

publishing {
    repositories {
        maven {
            setUrl("https://maven.pkg.github.com/ghaylansaada/springboot-security")
            credentials {
                username = project.findProperty("gpr.user") as String?
                password = project.findProperty("gpr.token") as String?
            }
        }
    }

    publications {
        create<MavenPublication>("gpr") {
            from(components["java"])
            groupId = "io.ghaylan.springboot"
            artifactId = "security"
            version = "1.0.0"
        }
    }
}
