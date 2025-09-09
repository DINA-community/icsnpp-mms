
add_compile_options(-Wextra -Wall -Wno-implicit-fallthrough -Wno-unused-variable -Werror)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/plugin/src/asn1c")

file(GLOB asn1c_files RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "plugin/src/asn1c/*.c")
add_library(asn1c OBJECT ${asn1c_files})
set_target_properties(asn1c PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(asn1c PRIVATE -fvisibility=hidden)
endif()

# The following executables are for testing purposes only
add_executable(test-parser $<TARGET_OBJECTS:asn1c> testing/Files/asn1c-test.c)
target_compile_definitions(test-parser PRIVATE PDU=MmsPdu)
