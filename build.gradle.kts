import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("io.spring.dependency-management") version "1.1.7"
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
    // Import Spring Boot's dependency versions (BOM)
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.5.5"))

    // --- Spring Security ---
    api("org.springframework.security:spring-security-web")
    api("org.springframework.security:spring-security-config")

    // --- Spring WebFlux + Boot ---
    implementation("org.springframework:spring-webflux")
    implementation("org.springframework.boot:spring-boot-autoconfigure")
    implementation("org.springframework.boot:spring-boot-starter-data-redis-reactive")

    // --- JWT ---
    implementation("io.jsonwebtoken:jjwt-api:0.13.0")
    implementation("io.jsonwebtoken:jjwt-impl:0.13.0")
    implementation("io.jsonwebtoken:jjwt-jackson:0.13.0")

    // --- Kotlin coroutines ---
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
}

kotlin {
    compilerOptions {
        javaParameters = true
        jvmTarget.set(JvmTarget.JVM_21)
        freeCompilerArgs.addAll(
            "-Xjsr305=strict",                       // strict nullability interop
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
