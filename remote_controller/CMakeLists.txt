cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS
    "../common_components/mathos_protocol"
    "../common_components/mathos_secure"
    "../common_components/mathos_messages"
    "../common_components/mathos_flight_modes"
    "../common_components/mathos_maintenance"
    "../common_components/mathos_identity"
    "../common_components/mathos_fleet"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(remote_controller)