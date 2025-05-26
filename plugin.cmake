
add_compile_options(-Wextra -Wall -Wno-implicit-fallthrough -Werror)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/plugin/src/asn1c")

# The following executables are for testing purposes only

file(GLOB asn1c_files RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "plugin/src/asn1c/*.c")
add_library(asn1c OBJECT ${asn1c_files})

add_executable(test-parser $<TARGET_OBJECTS:asn1c> testing/Files/asn1c-test.c)
target_compile_definitions(test-parser PRIVATE PDU=MmsPdu)
