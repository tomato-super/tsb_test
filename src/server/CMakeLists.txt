message(STATUS "building server ...")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BIN_OUTPUT_DIR})
set(OUTPUT_NAME "vmpq_server")

file(GLOB SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(${OUTPUT_NAME} ${SOURCE_FILES})

target_include_directories(${OUTPUT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/third_part/json
)

target_link_libraries(${OUTPUT_NAME} PRIVATE
    tsb_common
    pir_proto
)

message(STATUS "built server")