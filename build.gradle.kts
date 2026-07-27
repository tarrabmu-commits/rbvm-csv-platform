plugins {
    java
    application
}

group = "io.rbvm"
version = "0.5.0-SNAPSHOT"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}

application {
    mainClass.set("io.rbvm.csv.CsvPlatformServer")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(17)
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.register<JavaExec>("selfTest") {
    group = "verification"
    description = "Runs the dependency-free CSV contract test suite."
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("io.rbvm.csv.PlatformSelfTest")
    dependsOn(tasks.testClasses)
    enableAssertions = true
}

tasks.register<JavaExec>("analyzeCsv") {
    group = "application"
    description = "Analyzes one WAZUH_CSV_V1 file from the command line."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("io.rbvm.csv.CsvContractCli")
}
