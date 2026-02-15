# CMakeLists.txt — CyberSentinel LLM JNI bridge
#
# Builds libllama_jni.so for arm64-v8a only.
# Links llama.cpp + ggml statically to avoid multiple .so loading issues.
#
# Prerequisites:
#   - llama.cpp source tree at ${LLAMA_CPP_DIR} (set via build.gradle.kts)
#   - NDK r26+ (for C++17 support)
#
# Usage: Referenced by app/build.gradle.kts externalNativeBuild { cmake { ... } }

cmake_minimum_required(VERSION 3.22.1)
project(llama_jni LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# ── llama.cpp source directory (set from build.gradle.kts or default) ──
if(NOT DEFINED LLAMA_CPP_DIR)
    set(LLAMA_CPP_DIR "${CMAKE_SOURCE_DIR}/llama.cpp")
endif()

# ── Compile flags: optimize for size + performance on ARM64 ──
set(CMAKE_C_FLAGS_RELEASE   "${CMAKE_C_FLAGS_RELEASE}   -O3 -DNDEBUG -ffunction-sections -fdata-sections")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG -ffunction-sections -fdata-sections")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections -Wl,--strip-all")

# ── llama.cpp build options: CPU-only, minimal footprint ──
set(LLAMA_NATIVE       OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_TESTS  OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLAMA_BUILD_SERVER OFF CACHE BOOL "" FORCE)
set(LLAMA_CUDA         OFF CACHE BOOL "" FORCE)
set(LLAMA_METAL        OFF CACHE BOOL "" FORCE)
set(LLAMA_VULKAN       OFF CACHE BOOL "" FORCE)
set(LLAMA_SYCL         OFF CACHE BOOL "" FORCE)
set(GGML_CUDA          OFF CACHE BOOL "" FORCE)
set(GGML_METAL         OFF CACHE BOOL "" FORCE)
set(GGML_VULKAN        OFF CACHE BOOL "" FORCE)

# ── Add llama.cpp as subdirectory (builds ggml + llama as static libs) ──
add_subdirectory(${LLAMA_CPP_DIR} ${CMAKE_BINARY_DIR}/llama.cpp)

# ── JNI bridge library ──
add_library(llama_jni SHARED
    ${CMAKE_SOURCE_DIR}/llama_jni.cpp
)

# ── Include paths ──
target_include_directories(llama_jni PRIVATE
    ${LLAMA_CPP_DIR}/include
    ${LLAMA_CPP_DIR}/common
    ${LLAMA_CPP_DIR}/ggml/include
)

# ── Link: llama + ggml (static) + common + Android log ──
target_link_libraries(llama_jni
    llama
    common
    ggml
    android
    log
)
