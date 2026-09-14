cmake_minimum_required(VERSION 4.2)
project(Post_Quantum_Mail_Security)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --bind")

add_executable(Post_Quantum_Mail_Security main.cpp)

set_target_properties(Post_Quantum_Mail_Security PROPERTIES SUFFIX ".js")

if(EMSCRIPTEN)
    set_target_properties(WASM_Test PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/wasm"
    )
endif()