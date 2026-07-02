message(STATUS "building server ...")

file(GLOB SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
add_library(query_service ${SOURCE_FILES})


message(STATUS "built server")
