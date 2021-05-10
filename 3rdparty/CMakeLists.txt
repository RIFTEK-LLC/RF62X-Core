cmake_minimum_required(VERSION 3.13)



###############################################################################
## 3RD-PARTY
## dependencies for the project
###############################################################################
project(3rdparty LANGUAGES C)



###############################################################################
## SETTINGS
## basic 3rd-party settings before use
###############################################################################
# To inherit the top-level architecture when the project is used as a submodule.
SET(PARENT ${PARENT}_RF62X_CORE_3RDPARTY_)
# Disable self-overwriting of parameters inside included subdirectories.
SET(${PARENT}_SUBMODULE_CACHE_OVERWRITE OFF CACHE BOOL "" FORCE)



###############################################################################
## CONFIGURATION
## 3rd-party submodules configuration
###############################################################################
# RF627-Protocol
SET(${PARENT}_RF627_PROTOCOL_SUBMODULE                  ON CACHE BOOL "" FORCE)
if (${PARENT}_RF627_PROTOCOL_SUBMODULE)
    # library src
    SET(${PARENT}_RF627_PROTOCOL_LIB                    ON CACHE BOOL "" FORCE)
    # Examples
    SET(${PARENT}_RF627_PROTOCOL_EXAMPLES               OFF CACHE BOOL "" FORCE)
endif()

# RF62X-Protocol
SET(${PARENT}_RF62X_PROTOCOL_SUBMODULE                  ON CACHE BOOL "" FORCE)
if (${PARENT}_RF62X_PROTOCOL_SUBMODULE)
    # library src
    SET(${PARENT}_RF62X_PROTOCOL_LIB                    ON CACHE BOOL "" FORCE)
    # Examples
    SET(${PARENT}_RF62X_PROTOCOL_EXAMPLES               OFF CACHE BOOL "" FORCE)
endif()

# RF-PlatformUtils
SET(${PARENT}_RF_PLATFORM_UILS                          ON CACHE BOOL "" FORCE)
if (${PARENT}_RF_PLATFORM_UILS)
    # platform_methods
    SET(${PARENT}_PLATFORM_METHODS                      ON CACHE BOOL "" FORCE)
    # endian_conv
    SET(${PARENT}_ENDIAN_CONV                           ON CACHE BOOL "" FORCE)
    # custom_vector
    SET(${PARENT}_CUSTOM_VECTOR                         ON CACHE BOOL "" FORCE)
    # custom_string
    SET(${PARENT}_CUSTOM_STRING                         ON CACHE BOOL "" FORCE)
    # pthreads4w
    SET(${PARENT}_PTHREADS4W                            OFF CACHE BOOL "" FORCE)
    # getopt
    SET(${PARENT}_GETOPT                                OFF CACHE BOOL "" FORCE)
    # sandbox
    SET(${PARENT}_SANDBOX                               ON CACHE BOOL "" FORCE)
endif()



###############################################################################
## INCLUDING SUBDIRECTORIES
## Adding subdirectories according to the 3rd-party configuration
###############################################################################
# RF-PlatformUtils
if (${PARENT}_RF_PLATFORM_UILS)
    if (MSVC)
        SET(${PARENT}_PTHREADS4W    ON CACHE BOOL "" FORCE)
        SET(${PARENT}_GETOPT        ON CACHE BOOL "" FORCE)
    endif()
    add_subdirectory(RF-PlatformUtils)
endif()

# RF627-Protocol
if(${PARENT}_RF627_PROTOCOL_SUBMODULE)
    add_subdirectory(RF627-Protocol)
endif()

# RF62X-Protocol
if(${PARENT}_RF62X_PROTOCOL_SUBMODULE)
    add_subdirectory(RF62X-Protocol)
endif()
