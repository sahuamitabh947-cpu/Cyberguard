cmake_minimum_required(VERSION 3.16)
project(cyberguard_engine CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(WITH_PCAP "Enable live packet capture for the NIDS (needs libpcap)" ON)

find_package(Threads REQUIRED)
find_package(OpenSSL QUIET)

# Shared detection + ML code (used by the engine and the trainer)
add_library(cg_core STATIC
  src/url_analyzer.cpp
  src/text_analyzer.cpp
  src/anomaly_detector.cpp
  src/image_forensics.cpp
  src/audio_forensics.cpp
  src/log_analyzer.cpp
  src/risk_scorer.cpp
  src/url_parser.cpp
  src/model_registry.cpp
  src/ml/ml_core.cpp
  src/ml/linear_models.cpp
  src/ml/text_vectorizer.cpp
  src/ml/tree_models.cpp
  src/features/url_features.cpp
  src/features/nids_features.cpp
  src/features/behavior_features.cpp
  src/features/media_features.cpp
  src/nids/packet.cpp
  src/nids/nids_engine.cpp
  src/nids/live_capture.cpp
)
target_include_directories(cg_core PUBLIC include src)
target_link_libraries(cg_core PUBLIC Threads::Threads)
if(WIN32)
  # cpp-httplib sockets on native Windows builds (MSVC / MinGW)
  target_link_libraries(cg_core PUBLIC ws2_32 crypt32)
  target_compile_definitions(cg_core PUBLIC _WIN32_WINNT=0x0A00 NOMINMAX)
endif()

if(WITH_PCAP)
  find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
  find_library(PCAP_LIBRARY pcap)
  if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    message(STATUS "libpcap found: live NIDS capture enabled")
    target_compile_definitions(cg_core PUBLIC CG_WITH_PCAP)
    target_include_directories(cg_core PUBLIC ${PCAP_INCLUDE_DIR})
    target_link_libraries(cg_core PUBLIC ${PCAP_LIBRARY})
  else()
    message(WARNING "libpcap not found: live capture disabled (pcap file upload still works)")
  endif()
endif()

if(OpenSSL_FOUND)
  target_compile_definitions(cg_core PUBLIC CPPHTTPLIB_OPENSSL_SUPPORT)
  target_link_libraries(cg_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

add_executable(cyberguard_engine src/main.cpp)
target_link_libraries(cyberguard_engine PRIVATE cg_core)

# C++ model trainer: ./cg_train <datasets_dir> <models_dir> [all|text|url|nids|login|logs|image|audio]
add_executable(cg_train src/cg_train.cpp)
target_link_libraries(cg_train PRIVATE cg_core)
