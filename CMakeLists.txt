# CMake 최소 요구 버전
cmake_minimum_required(VERSION 3.10)

# 프로젝트 이름 설정
project(PacketParser C CXX)

# C++ 표준 설정
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 'parser'라는 이름의 실행 파일 생성
add_executable(parser
    src/main.cpp
    src/PacketParser.cpp
    src/protocols/BaseProtocolParser.cpp
    src/protocols/ModbusParser.cpp
    src/protocols/S7CommParser.cpp
    src/protocols/IProtocolParser.cpp
    src/protocols/XgtFenParser.cpp
    src/protocols/Dnp3Parser.cpp
    src/protocols/DnsParser.cpp
    src/protocols/GenericParser.cpp
    src/protocols/ArpParser.cpp
    src/protocols/UnknownParser.cpp
    src/protocols/TcpSessionParser.cpp
)

# --- 플랫폼에 따라 pcap 라이브러리 찾기 ---
if(WIN32)
    # Windows (Npcap/WinPcap SDK)
    # 사용자가 NPCAP_ROOT 경로를 직접 지정할 수 있도록 옵션을 추가합니다.
    # 예: cmake -B build -D NPCAP_ROOT="C:/Npcap-SDK"
    find_path(PCAP_INCLUDE_DIR pcap.h
        HINTS
            "${NPCAP_ROOT}/Include"               # 1. User-provided path
            "$ENV{NPCAP_SDK_PATH}/Include"        # 2. Environment variable
            "C:/Program Files/Npcap-SDK/Include"  # 3. Default install paths
            "C:/Npcap-SDK/Include"
            "C:/Program Files/Npcap/SDK/Include"
            "C:/Npcap/SDK/Include"
    )
    find_library(PCAP_LIBRARY NAMES wpcap
        HINTS
            "${NPCAP_ROOT}/Lib/x64"                # 1. User-provided path
            "$ENV{NPCAP_SDK_PATH}/Lib/x64"         # 2. Environment variable
            "C:/Program Files/Npcap-SDK/Lib/x64"   # 3. Default install paths (for x64)
            "C:/Npcap-SDK/Lib/x64"
            "C:/Program Files/Npcap/SDK/Lib/x64"
            "C:/Npcap/SDK/Lib/x64"
            "${NPCAP_ROOT}/Lib"                    # Fallback for different structures
            "$ENV{NPCAP_SDK_PATH}/Lib"
            "C:/Program Files/Npcap-SDK/Lib"
            "C:/Npcap-SDK/Lib"
    )
    # Windows 소켓 라이브러리 추가
    target_link_libraries(parser PRIVATE ${PCAP_LIBRARY} ws2_32)
else()
    # macOS / Linux
    find_path(PCAP_INCLUDE_DIR pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)
    target_link_libraries(parser PRIVATE ${PCAP_LIBRARY})
endif()

# pcap 라이브러리를 찾지 못하면 에러 발생
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "Could not find pcap library. Please install Npcap SDK (Windows) or libpcap-dev (Linux/macOS), or specify the path with -D NPCAP_ROOT=<path_to_npcap_sdk>")
endif()

# 헤더 파일 검색 경로 추가
target_include_directories(parser PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    ${PCAP_INCLUDE_DIR}
)

