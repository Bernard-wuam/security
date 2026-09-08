
add_library(Security INTERFACE)
add_library(Security::Security ALIAS Security)

target_sources(
    Security
    INTERFACE
    FILE_SET HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
    FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/security/security.h
)

if(NOT Security::Security)
    find_package(Security CONFIG QUIET)

    if(NOT Security_FOUND)
        include(FetchContent)

        FetchContent_Declare(
            ServerError
            GIT_REPOSITORY https://github.com/Bernard-wuam/servererror.git
            GIT_TAG main
        )
        FetchContent_MakeAvailable(ServerError)
    endif()
endif()

target_link_libraries(Security INTERFACE ServerError)

install(
    TARGETS Security
    EXPORT SecurityTargets
    FILE_SET HEADERS
)

install(
    EXPORT SecurityTargets
    DESTINATION share/cmake/security
    NAMESPACE Security::
)

include(CMakePackageConfigHelpers)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/securityConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/SecurityConfig.cmake
    INSTALL_DESTINATION share/cmake/security)

write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/SecurityConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

install(
    FILES
    ${CMAKE_CURRENT_BINARY_DIR}/SecurityConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/SecurityConfigVersion.cmake
    DESTINATION share/cmake/security
)
