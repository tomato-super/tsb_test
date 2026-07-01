file(GLOB COMMON_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

add_library(tsb_common ${COMMON_FILES})

target_include_directories(tsb_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(tsb_common PUBLIC
    Cryptopp::Cryptopp
)
