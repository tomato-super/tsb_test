message(STATUS "building client ...")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BIN_OUTPUT_DIR})
set(OUTPUT_NAME "query_client")

file(GLOB SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(${OUTPUT_NAME} ${SOURCE_FILES})

target_include_directories(${OUTPUT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/third_part/json
)

target_link_libraries(${OUTPUT_NAME} PRIVATE
    pir_proto
    tsb_common
)

message(STATUS "built client")