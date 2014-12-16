add_library (vmpc STATIC SHARED vmpc_encrypt.c)
target_include_directories (vmpc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
