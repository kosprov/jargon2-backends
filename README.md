# Jargon2 Backends: Argon2 implementations for the Jargon2 API 

[![Build Status](https://travis-ci.org/kosprov/jargon2-backends.svg?branch=master)](https://travis-ci.org/kosprov/jargon2-backends)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/14708/badge.svg)](https://scan.coverity.com/projects/kosprov-jargon2-backends)
[![Maven metadata URI](https://img.shields.io/maven-metadata/v/http/central.maven.org/maven2/com/kosprov/jargon2/jargon2-native-ri-backend/maven-metadata.xml.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.kosprov.jargon2%22%20AND%20a%3A%22jargon2-native-ri-backend%22)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=com.kosprov.jargon2%3Ajargon2-backends&metric=alert_status)](https://sonarcloud.io/dashboard/index/com.kosprov.jargon2:jargon2-backends)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=com.kosprov.jargon2%3Ajargon2-backends&metric=security_rating)](https://sonarcloud.io/dashboard/index/com.kosprov.jargon2:jargon2-backends)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](/LICENSE)

This repository aims to be a collection of `com.kosprov.jargon2.spi.Jargon2Backend` SPI implementations, ready to be plugged into the Jargon2 API. Artifacts contain all service provider metadata and can be used by simply adding them into the runtime classpath.

## Security considerations

This section summarizes any security considerations that come with the use of this library. Make sure you evaluate them before choosing to use any of the Jargon2 backends provided here and visit this section regularly for any updates.

| Item |  Description |
| ---  | --- |
| Default backend native library can be bypassed | If you're using the default backend (`jargon2-native-ri-backend`), the shared library it binds to can be overridden by defining one of `-Djna.boot.library.path`, `-Djna.library.path` and `-Djna.nosys` system properties. See [Hardening your environment](#hardening-your-environment) for more details. |


## The default backend

Currently, there is only one implementation named `jargon2-native-ri-backend` that wraps the [Argon2 reference implementation](https://github.com/P-H-C/phc-winner-argon2 "Argon2 reference implementation repository"). It's unique characteristic is that it binds directly to the low-level API of the C code. This allows for two distinctive features of the high-level Jargon2 API:

- Ability to set memory lanes and threads independently
- Leverage Argon2 RI API for keyed-hashing and additional authentication data (AAD)

### Usage

Simply add this dependency:

```xml
<dependency>
    <groupId>com.kosprov.jargon2</groupId>
    <artifactId>jargon2-native-ri-backend</artifactId>
    <version>1.1.1</version>
    <scope>runtime</scope>
</dependency>
```

`jargon2-native-ri-backend` contains `META-INF/services/com.kosprov.jargon2.spi.Jargon2Backend` metadata and is automatically discovered by Jargon2's discovery process. No build time dependency is necessary, so it's recommended to keep `scope` to `runtime`. 

### Pre-packaged binaries

To make adopting Jargon2 as easy as possible, `jargon2-native-ri-backend` has a transitive dependency to `jargon2-native-ri-binaries-generic`, an artifact that contains binaries of the reference implementation. They are available for Windows, Linux and macOS (x86-64 only), so it should work as-is on most systems.

Release `1.1.1` of `jargon2-native-ri-binaries-generic` contains binaries built from Argon2 release [20171227](https://github.com/P-H-C/phc-winner-argon2/releases/tag/20171227 "Argon2 RI release 20171227").

### Using different binaries

There are at least three reasons why one would need to use different binaries than those included in `jargon2-native-ri-binaries-generic`:

- Custom-built for a particular x86 micro-architecture
    
    The reference implementation contains a number of optimizations on the low-level algorithms of Argon2 and Blake2b that utilize SIMD instructions on modern processors. Expect a significant performance boost just by recompiling the C code for your particular CPU type. The gains are bigger if you're hashing with large memory and time costs.

- Different architecture

    Binaries are available only for the x86 architecture, so different processor architectures would need their own binaries.
    
- Security patches

    If Argon2 RI releases security patches, you would always have the option to recompile and switch to the patched binaries.

To change the binaries you have two options:

- Build Argon2 RI and install it as a system library

    `jargon2-native-ri-backend` uses [JNA](https://github.com/java-native-access/jna) to dynamically invoke native code. JNA searches for system libraries first, so installing on `/usr/lib/libargon2.so` will take precedence over the classpath binaries. You can change the search location by setting the `-Djna.library.path` property.

- Tweak Maven dependencies

    If installing native libraries on the host OS is not very convenient, you can package your binaries in a jar and add that to your application. Don't forget to exclude the transitive dependency to `jargon2-native-ri-binaries-generic`.
    
    ```xml
    <dependency>
        <groupId>com.kosprov.jargon2</groupId>
        <artifactId>jargon2-native-ri-backend</artifactId>
        <version>1.1.1</version>
        <scope>runtime</scope>
        <exclusions>
            <!-- exclude transitive dependency to generic binaries -->
            <exclusion>
                <groupId>com.kosprov.jargon2</groupId>
                <artifactId>jargon2-native-ri-binaries-generic</artifactId>
            </exclusion>
        </exclusions>
    </dependency>
    <!-- add dependency to optimized binaries -->
    <dependency>
        <groupId>com.mycompany.jargon2</groupId>
        <artifactId>my-argon2-optimized-binaries</artifactId>
        <version>1.0.0</version>
        <scope>runtime</scope>
    </dependency>
    ```
    Have a look at `jargon2-native-ri-binaries-generic` to see the folder structure required by JNA.
    
If you're having doubts on which Argon2 binaries are loaded, start the JVM with `-Djna.debug_load=true`.

### Hardening your environment

JNA searches for libraries in locations that can be can be controlled with `-Djna.boot.library.path`, `-Djna.library.path` and `-Djna.nosys` system properties. Keep your security engineers alerted and have them scan or change-detect for improper use of these properties. Make sure they protect them as they would protect JAAS login module or security manager system properties and configuration files. Changing those system properties so that a malicius native library gets loaded, will leak all your user's passwords.

If you are using SELinux, loading the native library from the classpath (as `jargon2-native-ri-binaries-generic` does) may not work. You would have to install the library in an accessible location. You can also define `-Djna.nounpack=true` to make sure the library is never unpacked from the classpath.