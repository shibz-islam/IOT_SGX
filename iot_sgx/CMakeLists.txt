cmake_minimum_required(VERSION 3.12)
project(IoTEnclave)

set(CMAKE_CXX_STANDARD 11)

set(sigsegv_INCLUDE_DIR /usr/local/include/)
set(sigsegv_LIBRARIES /usr/local/lib/libsigsegv.a)

include_directories(App)
include_directories(Enclave)
include_directories(Include)

add_executable(IoTEnclave
        App/Edger8rSyntax/Arrays.cpp
        App/Edger8rSyntax/Functions.cpp
        App/Edger8rSyntax/Pointers.cpp
        App/Edger8rSyntax/Types.cpp
        App/TrustedLibrary/Libc.cpp
        App/TrustedLibrary/Libcxx.cpp
        App/TrustedLibrary/Thread.cpp
        App/App.cpp
        App/App.h
        Enclave/Edger8rSyntax/Arrays.cpp
        Enclave/Edger8rSyntax/Functions.cpp
        Enclave/Edger8rSyntax/Pointers.cpp
        Enclave/Edger8rSyntax/Types.cpp
        Enclave/TrustedLibrary/Libc.cpp
        Enclave/TrustedLibrary/Libcxx.cpp
        Enclave/TrustedLibrary/Thread.cpp
        Enclave/Enclave.cpp
        Enclave/Enclave.h
        Include/user_types.h
        Include/analytics_utils.cpp Include/analytics_utils.h App/Sensor.cpp App/Sensor.h App/SocketConnection.cpp App/SocketConnection.h App/JSONParser.cpp App/JSONParser.h App/CurlHelper.cpp App/CurlHelper.h MongoHelper.cpp MongoHelper.h App/aes_gcm.cpp App/aes_gcm.h Enclave/RuleBase.cpp Enclave/RuleBase.h Enclave/MessageParser.cpp Enclave/MessageParser.h Enclave/EnclaveHelper.cpp Enclave/EnclaveHelper.h Enclave/Constants.h)

target_link_libraries(IoTEnclave ${sigsegv_LIBRARIES})