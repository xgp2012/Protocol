cmake_minimum_required(VERSION 3.20)

project(Protocol VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(FetchContent)

set(CMAKE_FIND_PACKAGE_PREFER_CONFIG ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PROTOCOL_ENABLE_DETAIL_ERRORS "Enable detailed error information" OFF)
option(PROTOCOL_ENABLE_CODEC "Enable codec features" ON)
option(PROTOCOL_ENABLE_AUTHENTICATION "Enable authentication features" ON)
option(PROTOCOL_ENABLE_CONNECTION "Enable connection features" OFF)
option(PROTOCOL_ENABLE_EXCEPTIONS "Enable C++ exceptions for Protocol target" OFF)

if(PROTOCOL_ENABLE_CONNECTION AND NOT PROTOCOL_ENABLE_CODEC)
    message(FATAL_ERROR
        "Invalid configuration: CONNECTION requires CODEC. "
        "Set PROTOCOL_ENABLE_CODEC=ON or PROTOCOL_ENABLE_CONNECTION=OFF."
    )
endif()

set(PROTOCOL_SOURCES)
set(PROTOCOL_INSTALL_INCLUDE_DIRS)

if(PROTOCOL_ENABLE_CODEC)
    file(GLOB_RECURSE PROTOCOL_SOURCES_CODEC CONFIGURE_DEPENDS
        "${PROJECT_SOURCE_DIR}/src/sculk/protocol/codec/*.cpp"
    )
    list(APPEND PROTOCOL_SOURCES ${PROTOCOL_SOURCES_CODEC})
    list(APPEND PROTOCOL_INSTALL_INCLUDE_DIRS "sculk/protocol/codec")
endif()

if(PROTOCOL_ENABLE_AUTHENTICATION)
    file(GLOB_RECURSE PROTOCOL_SOURCES_AUTH CONFIGURE_DEPENDS
        "${PROJECT_SOURCE_DIR}/src/sculk/protocol/auth/*.cpp"
    )
    list(APPEND PROTOCOL_SOURCES ${PROTOCOL_SOURCES_AUTH})
    list(APPEND PROTOCOL_INSTALL_INCLUDE_DIRS "sculk/protocol/auth")
endif()

if(PROTOCOL_ENABLE_CONNECTION)
    file(GLOB_RECURSE PROTOCOL_SOURCES_CONNECTION CONFIGURE_DEPENDS
        "${PROJECT_SOURCE_DIR}/src/sculk/protocol/connection/*.cpp"
    )
    list(APPEND PROTOCOL_SOURCES ${PROTOCOL_SOURCES_CONNECTION})
    list(APPEND PROTOCOL_INSTALL_INCLUDE_DIRS "sculk/protocol/connection")
endif()

add_library(Protocol STATIC)
add_library(Protocol::Protocol ALIAS Protocol)

if(PROTOCOL_ENABLE_AUTHENTICATION OR PROTOCOL_ENABLE_CONNECTION)
    set(OPENSSL_USE_STATIC_LIBS ON)
    find_package(OpenSSL 3 REQUIRED)
    target_link_libraries(Protocol PRIVATE OpenSSL::Crypto)

    FetchContent_Declare(
        reflection
        GIT_REPOSITORY https://github.com/SculkCatalystMC/Reflection.git
        GIT_TAG main
    )
    FetchContent_MakeAvailable(reflection)
    target_link_libraries(Protocol PRIVATE $<BUILD_INTERFACE:reflection::reflection>)
else()
    if(PROTOCOL_ENABLE_CODEC)
        FetchContent_Declare(
            magic_enum
            GIT_REPOSITORY https://github.com/Neargye/magic_enum.git
            GIT_TAG v0.9.7
        )
        FetchContent_MakeAvailable(magic_enum)
        target_link_libraries(Protocol PRIVATE $<BUILD_INTERFACE:magic_enum::magic_enum>)
    endif()
endif()

if(PROTOCOL_ENABLE_AUTHENTICATION)
    set(HTTPLIB_INSTALL OFF CACHE BOOL "Disable cpp-httplib install targets" FORCE)
    set(HTTPLIB_COMPILE OFF CACHE BOOL "Use cpp-httplib header-only mode" FORCE)
    set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE ON CACHE BOOL "Enable OpenSSL for HTTPS in cpp-httplib" FORCE)
    set(HTTPLIB_REQUIRE_OPENSSL ON CACHE BOOL "Require OpenSSL for cpp-httplib HTTPS" FORCE)
    set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "Disable optional zlib for cpp-httplib" FORCE)
    set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "Disable optional brotli for cpp-httplib" FORCE)

    FetchContent_Declare(
        cpp_httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG v0.45.0
    )
    FetchContent_MakeAvailable(cpp_httplib)

    if(TARGET httplib::httplib)
        target_link_libraries(Protocol PRIVATE $<BUILD_INTERFACE:httplib::httplib> OpenSSL::SSL)
    else()
        target_include_directories(Protocol PRIVATE $<BUILD_INTERFACE:${cpp_httplib_SOURCE_DIR}>)
    endif()

    target_compile_definitions(Protocol PRIVATE
        CPPHTTPLIB_OPENSSL_SUPPORT
        CPPHTTPLIB_NO_EXCEPTIONS
    )
endif()

if(PROTOCOL_SOURCES)
    target_sources(Protocol PRIVATE ${PROTOCOL_SOURCES})
endif()

set_target_properties(Protocol PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    LINKER_LANGUAGE CXX
)

target_compile_features(Protocol PUBLIC cxx_std_23)

target_include_directories(Protocol PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(PROTOCOL_ENABLE_DETAIL_ERRORS)
    target_compile_definitions(Protocol PUBLIC SCULK_PROTOCOL_ENABLE_DETAIL_ERRORS)
endif()

if(MSVC)
    if(NOT PROTOCOL_ENABLE_EXCEPTIONS)
        string(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
    endif()

    target_compile_options(Protocol PRIVATE
        /W4
        /utf-8
        $<$<NOT:$<BOOL:${PROTOCOL_ENABLE_EXCEPTIONS}>>:/EHs-c->
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:RelWithDebInfo>:/O2>
    )
    target_compile_definitions(Protocol PRIVATE
        UNICODE
        NOMINMAX
        $<$<NOT:$<BOOL:${PROTOCOL_ENABLE_EXCEPTIONS}>>:_HAS_EXCEPTIONS=0>
    )
else()
    target_compile_options(Protocol PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        $<$<NOT:$<BOOL:${PROTOCOL_ENABLE_EXCEPTIONS}>>:-fno-exceptions>
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:RelWithDebInfo>:-O3>
    )
endif()

install(TARGETS Protocol
    EXPORT ProtocolTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

foreach(PROTOCOL_INCLUDE_DIR ${PROTOCOL_INSTALL_INCLUDE_DIRS})
    install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/${PROTOCOL_INCLUDE_DIR}/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROTOCOL_INCLUDE_DIR}
        OPTIONAL
    )
endforeach()

configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/cmake/ProtocolConfig.cmake.in
    ${PROJECT_BINARY_DIR}/ProtocolConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Protocol
)

write_basic_package_version_file(
    ${PROJECT_BINARY_DIR}/ProtocolConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(EXPORT ProtocolTargets
    FILE ProtocolTargets.cmake
    NAMESPACE Protocol::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Protocol
)

install(FILES
    ${PROJECT_BINARY_DIR}/ProtocolConfig.cmake
    ${PROJECT_BINARY_DIR}/ProtocolConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Protocol
)