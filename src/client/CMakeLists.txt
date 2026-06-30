message(STATUS "building client ...")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(OUTPUT_NAME "query_client")

file(GLOB SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(${OUTPUT_NAME} ${SOURCE_FILES})

target_include_directories(${OUTPUT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../common
)

target_link_libraries(${OUTPUT_NAME} PRIVATE
    ${Cryptopp_LIBRARY}
)

message(STATUS "built client")
