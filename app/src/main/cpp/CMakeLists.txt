# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.18.1)

# Declares and names the project.
project("integritycheck")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.
add_library(local_openssl STATIC IMPORTED)
add_library(local_crypto STATIC IMPORTED)

add_library( # Sets the name of the library.
        integritycheck

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        MemoryVerifier/IntegrityCheck.h
        MemoryVerifier/IntegrityCheck.cpp
        MemoryVerifier/Common.h
        MemoryVerifier/Utils.h
        MemoryVerifier/Utils.cpp
        libmem.h
        libmem.c
        iterate.cpp
        native-lib.cpp)


set_target_properties(local_crypto PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/lib/${ANDROID_ABI}/libcrypto.a)
set_target_properties(local_openssl PROPERTIES IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/lib/${ANDROID_ABI}/libssl.a)

find_library(z-lib z)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)
find_package(ZLIB REQUIRED)
# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
        integritycheck

        # Links the target library to the log library
        # included in the NDK.
        local_openssl
        local_crypto
        ${z-lib}
        ${log-lib})



