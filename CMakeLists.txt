cmake_minimum_required(VERSION 3.16)
project(sarek LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── sarek_keyring ─────────────────────────────────────────────────────────────
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../keyring
                 ${CMAKE_CURRENT_BINARY_DIR}/keyring_build)

# ── Dependencies ──────────────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)
find_package(yaml-cpp REQUIRED)
find_package(Threads REQUIRED)

find_library(BDB_LIB NAMES db-5.3 db-5 db5 db
    PATHS /usr/lib64 /usr/lib /usr/local/lib REQUIRED)
find_path(BDB_INC db.h
    PATHS /usr/include /usr/local/include REQUIRED)

find_library(FYAML_LIB fyaml REQUIRED HINTS /usr/local/lib)
find_path(FYAML_INC libfyaml.h REQUIRED HINTS /usr/local/include)

find_library(JSON_C_LIB json-c REQUIRED HINTS /usr/local/lib64 /usr/local/lib /usr/lib64 /usr/lib)
find_path(JSON_C_INC json-c/json.h REQUIRED HINTS /usr/local/include /usr/include)

# libcrystals (installed) + its transitive dynamic deps
# Override CRYSTALS_LIB and CRYSTALS_INC via -D flags to use a dev build, e.g.:
#   cmake -S sarek -B sarek/build \
#     -DCRYSTALS_LIB=/path/to/libcrystals.a \
#     -DCRYSTALS_INC=/path/to/libcrystals/include
find_library(CRYSTALS_LIB  crystals-1.2 PATHS /usr/local/lib REQUIRED)
find_library(XKCP_LIB      XKCP         PATHS /usr/local/lib REQUIRED)
find_library(BLAKE3_LIB   blake3
    PATHS /mnt/c/Users/daves/OneDrive/Desktop/Crystals/local/lib64 REQUIRED)
find_library(TBB_LIB      tbb
    PATHS /usr/lib64 /mnt/c/Users/daves/OneDrive/Desktop/Crystals/local/lib64 REQUIRED)

# Header-only deps for modules that call crystals internals directly
set(MSGPACK_INC /mnt/c/Users/daves/OneDrive/Desktop/Crystals/msgpack-c/include)
set(SCRYPT_KDF_INC /mnt/c/Users/daves/OneDrive/Desktop/Crystals/scrypt/libscrypt-kdf)
set(CRYSTALS_INC /usr/local/include CACHE PATH "Path to crystals public headers (parent of crystals/)")
set(XKCP_INC /mnt/c/Users/daves/OneDrive/Desktop/Crystals/XKCP/bin/x86-64/libXKCP.so.headers)

# ── spdlog (compiled for performance) ─────────────────────────────────────────
set(SPDLOG_DIR /mnt/c/Users/daves/OneDrive/Desktop/SAREK/spdlog)
set(SPDLOG_INC ${SPDLOG_DIR}/include)
add_library(spdlog_compiled STATIC
    ${SPDLOG_DIR}/src/spdlog.cpp
    ${SPDLOG_DIR}/src/stdout_sinks.cpp
    ${SPDLOG_DIR}/src/color_sinks.cpp
    ${SPDLOG_DIR}/src/file_sinks.cpp
    ${SPDLOG_DIR}/src/async.cpp
    ${SPDLOG_DIR}/src/cfg.cpp
    ${SPDLOG_DIR}/src/bundled_fmtlib_format.cpp
)
target_include_directories(spdlog_compiled PUBLIC ${SPDLOG_INC})
target_compile_definitions(spdlog_compiled PUBLIC SPDLOG_COMPILED_LIB)
target_compile_options(spdlog_compiled PRIVATE -w)   # suppress spdlog warnings

# ── Module 0: log ──────────────────────────────────────────────────────────────
add_library(sarek_log STATIC log/log.cpp)
target_include_directories(sarek_log PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sarek_log PUBLIC spdlog_compiled Threads::Threads)
target_compile_options(sarek_log PRIVATE -Wall -Wextra)

# ── Module 1: config ──────────────────────────────────────────────────────────
add_library(sarek_config STATIC
    config/config.cpp
)
target_include_directories(sarek_config PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(sarek_config PUBLIC yaml-cpp sarek_log)
target_compile_options(sarek_config PRIVATE -Wall -Wextra)

add_executable(sarek_config_test
    config/test_config.cpp
)
target_link_libraries(sarek_config_test PRIVATE sarek_config)
target_compile_options(sarek_config_test PRIVATE -Wall -Wextra)

# ── Module 2: db ──────────────────────────────────────────────────────────────
add_library(sarek_db STATIC
    db/db.cpp
)
target_include_directories(sarek_db PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${BDB_INC}
)
target_link_libraries(sarek_db PUBLIC ${BDB_LIB} sarek_log sarek_keyring)
target_compile_options(sarek_db PRIVATE -Wall -Wextra)

add_executable(sarek_db_test
    db/test_db.cpp
)
target_link_libraries(sarek_db_test PRIVATE sarek_db)
target_compile_options(sarek_db_test PRIVATE -Wall -Wextra)

# ── Module 3: cache (header-only) ────────────────────────────────────────────
add_library(sarek_cache INTERFACE)
target_include_directories(sarek_cache INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(sarek_cache_test
    cache/test_cache.cpp
)
target_link_libraries(sarek_cache_test PRIVATE sarek_cache Threads::Threads)
target_compile_options(sarek_cache_test PRIVATE -Wall -Wextra)

# ── Module 4: bootstrap ───────────────────────────────────────────────────────
add_library(sarek_bootstrap STATIC
    bootstrap/user_record.cpp
    bootstrap/bootstrap.cpp
)
target_include_directories(sarek_bootstrap PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CRYSTALS_INC}
    ${XKCP_INC}
)
target_include_directories(sarek_bootstrap PRIVATE
    ${MSGPACK_INC}
    ${SCRYPT_KDF_INC}
)
target_link_libraries(sarek_bootstrap PUBLIC
    sarek_config
    sarek_db
    sarek_log
    ${CRYSTALS_LIB}
    ${XKCP_LIB}
    ${BLAKE3_LIB}
    ${TBB_LIB}
    OpenSSL::Crypto
    yaml-cpp
)
target_compile_options(sarek_bootstrap PRIVATE -Wall -Wextra)

add_executable(sarek_bootstrap_test
    bootstrap/test_bootstrap.cpp
)
target_link_libraries(sarek_bootstrap_test PRIVATE sarek_bootstrap)
target_compile_options(sarek_bootstrap_test PRIVATE -Wall -Wextra)

# ── Module 5: auth ────────────────────────────────────────────────────────────
add_library(sarek_auth STATIC
    auth/auth.cpp
)
target_include_directories(sarek_auth PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CRYSTALS_INC}
)
target_include_directories(sarek_auth PRIVATE
    ${MSGPACK_INC}
)
target_link_libraries(sarek_auth PUBLIC sarek_bootstrap)
target_compile_options(sarek_auth PRIVATE -Wall -Wextra)

add_executable(sarek_auth_test
    auth/test_auth.cpp
)
target_link_libraries(sarek_auth_test PRIVATE sarek_auth Threads::Threads)
target_compile_options(sarek_auth_test PRIVATE -Wall -Wextra)

# ── Module 6: vault ───────────────────────────────────────────────────────────
add_library(sarek_vault STATIC
    vault/vault.cpp
)
target_include_directories(sarek_vault PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CRYSTALS_INC}
)
target_include_directories(sarek_vault PRIVATE
    ${MSGPACK_INC}
    ${XKCP_INC}
)
target_link_libraries(sarek_vault PUBLIC
    sarek_auth
    sarek_log
    ${CRYSTALS_LIB}
    ${XKCP_LIB}
    ${BLAKE3_LIB}
    ${TBB_LIB}
    OpenSSL::Crypto
)
target_compile_options(sarek_vault PRIVATE -Wall -Wextra)

add_executable(sarek_vault_test
    vault/test_vault.cpp
)
target_link_libraries(sarek_vault_test PRIVATE sarek_vault)
target_compile_options(sarek_vault_test PRIVATE -Wall -Wextra)

# ── Module 7: http ────────────────────────────────────────────────────────────
add_library(sarek_http STATIC
    http/http.cpp
)
target_include_directories(sarek_http PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CRYSTALS_INC}
)
target_include_directories(sarek_http PRIVATE ${FYAML_INC} ${JSON_C_INC})
target_link_libraries(sarek_http PUBLIC
    sarek_vault
    sarek_log
    OpenSSL::SSL
    ${FYAML_LIB}
    ${JSON_C_LIB}
)
target_compile_options(sarek_http PRIVATE -Wall -Wextra)

# ── Module 8: sarek server executable ────────────────────────────────────────
add_executable(sarek
    main.cpp
)
target_include_directories(sarek PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CRYSTALS_INC}
    ${XKCP_INC}
)
target_link_libraries(sarek PRIVATE sarek_http sarek_log)
target_compile_options(sarek PRIVATE -Wall -Wextra)
