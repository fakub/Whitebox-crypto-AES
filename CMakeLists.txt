cmake_minimum_required(VERSION 3.3)
project(Whitebox_crypto_AES)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    base.h
    BGEAttack.cpp
    BGEAttack.h
    BGEAttack_test.cpp
    GenericAES.cpp
    GenericAES.h
    LinearAffineEq.cpp
    LinearAffineEq.h
    LinearAffineEq_test.cpp
    main.cpp
    md5.c
    md5.h
    MixingBijections.cpp
    MixingBijections.h
    NTLUtils.cpp
    NTLUtils.h
    probInvMatrix8.m
    testing.cpp
    testing.h
    WBAES.cpp
    WBAES.h
    WBAESGenerator.cpp
    WBAESGenerator.h hex_tools.h)

add_executable(Whitebox_crypto_AES ${SOURCE_FILES})