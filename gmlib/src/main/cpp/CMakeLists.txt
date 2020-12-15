# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

#set(openssl ${CMAKE_SOURCE_DIR}/gm_include/openssl)
#set(gmssl_dir ${CMAKE_SOURCE_DIR}/gm_include)

set(lib_dir ${CMAKE_SOURCE_DIR}/../jniLibs)

add_library(libssl STATIC IMPORTED)
set_target_properties(libssl PROPERTIES IMPORTED_LOCATION
        ${lib_dir}/${ANDROID_ABI}/libssl.a)

add_library(libcrypto STATIC IMPORTED)
set_target_properties(libcrypto PROPERTIES IMPORTED_LOCATION
        ${lib_dir}/${ANDROID_ABI}/libcrypto.a)


add_library( # Sets the name of the library.
             gmssl

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
        GmSSL.cpp)

find_library( # Sets the name of the path variable.
        log-lib
        z

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log )

target_include_directories(gmssl PRIVATE ${CMAKE_SOURCE_DIR}/gm_include)
target_link_libraries( # Specifies the target library.
        gmssl

        libssl
        libcrypto

        # Links the target library to the log library
        # included in the NDK.
        ${log-lib}
        z
        log )