cmake_minimum_required(VERSION 4.2)
project(WASM_Crypto)

set(CMAKE_CXX_STANDARD 20)

# Izmeniti shodno pravoj putanji do build-ovane liboqs biblioteke
set(PQC_WASM_PREFIX "C:/Users/Branislav Bajic/DEV_TOOLS/pqc/install-wasm")

set(CMAKE_EXE_LINKER_FLAGS
        "${CMAKE_EXE_LINKER_FLAGS} --bind -s ALLOW_MEMORY_GROWTH=1 -s STACK_SIZE=8388608 -s DYNAMIC_EXECUTION=0")

add_executable(WASM_Crypto main.cpp)

set_target_properties(WASM_Crypto PROPERTIES SUFFIX ".js")

if(EMSCRIPTEN)
    set_target_properties(WASM_Crypto PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/wasm"
    )
endif()

target_include_directories(WASM_Crypto PRIVATE "${PQC_WASM_PREFIX}/include")
target_link_directories(WASM_Crypto PRIVATE "${PQC_WASM_PREFIX}/lib")
target_link_libraries(WASM_Crypto PRIVATE oqs)

# liboqs-cpp needs these defined by whatever build system consumes it
target_compile_definitions(WASM_Crypto PRIVATE
        LIBOQS_CPP_VERSION_NUM=0.12.0
        LIBOQS_CPP_VERSION_STR="0.12.0"
        LIBOQS_CPP_VERSION="0.12.0"
)