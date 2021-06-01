message(STATUS "building submodules")
execute_process(COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/build.sh WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
