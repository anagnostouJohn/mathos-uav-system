# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS
    "../common_components/mathos_protocol"
    "../common_components/mathos_secure"
    "../common_components/mavlink"
    "../common_components/mathos_messages"
    "../common_components/mathos_flight_modes"
    "../common_components/mathos_maintenance"
    "../common_components/mathos_identity"
    "../common_components/mathos_fleet"
)

set(COMPONENTS
    main
    mathos_protocol
    mathos_secure
    mavlink
    mathos_messages
    mathos_flight_modes
    mathos_maintenance
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(drone_gateway)