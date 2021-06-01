#pragma once

#include "../../common/helib_kats.h"
#include "dasta_5_helib.h"

using namespace DASTA_5;

// build an array of KnownAnswerTests for DASTA_128
HElibKnownAnswerTest<DASTA_128_HElib> KNOWN_ANSWER_TESTS[] = {
    {
        {0x76, 0xad, 0x7b, 0x3f, 0x23, 0xe9, 0x58, 0x09, 0x47, 0x7c, 0xb8,
         0x14, 0xcc, 0x35, 0xec, 0x1e, 0xa6, 0x1e, 0xba, 0xfe, 0x80, 0x43,
         0x22, 0x62, 0x87, 0x65, 0x59, 0x58, 0x56, 0x2e, 0x6c, 0x98, 0x6e,
         0x45, 0xdc, 0xed, 0x34, 0x43, 0x0d, 0xc7, 0x87, 0x13, 0x0c, 0x04,
         0x73, 0x91, 0xbd, 0xfe, 0x34, 0x17, 0x4c, 0xee, 0xc7, 0x44, 0x85,
         0x99, 0xe2, 0x14, 0xe1, 0x55, 0xd3, 0x70, 0x14, 0xa4, 0xdb, 0x20},
        {0x43, 0x1d, 0xcb, 0x7d, 0xed, 0xdf, 0x80, 0xba, 0x21, 0x62, 0xed,
         0x01, 0xf1, 0x4f, 0x23, 0xe5, 0x36, 0x9b, 0x18, 0xc5, 0x24, 0x00,
         0x9e, 0x47, 0x46, 0xad, 0x85, 0xfe, 0x9e, 0x43, 0x1d, 0xbe, 0x7a,
         0x08, 0x9f, 0x48, 0x94, 0x12, 0x2e, 0xc4, 0xaf, 0x82, 0xe6, 0x4f,
         0xb1, 0x88, 0x8b, 0xb9, 0xa1, 0x11, 0x84, 0x2f, 0x66, 0x41, 0x47,
         0xf4, 0x91, 0x6e, 0x8c, 0x7b, 0x44, 0x93, 0x21, 0x7b, 0x17, 0x50},
        {0xbf, 0x5f, 0x03, 0x4c, 0x26, 0x3b, 0xbd, 0xd4, 0x0c, 0xc0, 0x6e,
         0xd3, 0x81, 0xa4, 0x59, 0xde, 0xec, 0xd3, 0xd8, 0xdb, 0xb6, 0x71,
         0xc3, 0xa1, 0xde, 0x3d, 0x13, 0x4b, 0x84, 0x28, 0x51, 0x43, 0x0c,
         0x71, 0x9a, 0x7c, 0x01, 0x97, 0x9f, 0x26, 0x84, 0xfb, 0x9d, 0x90,
         0xf6, 0x1d, 0x64, 0xab, 0x12, 0x3f, 0x66, 0xc8, 0xde, 0xa1, 0xde,
         0xb5, 0xc9, 0x30, 0x24, 0xb6, 0xcd, 0xda, 0x15, 0x2b, 0x0a, 0x60},
        0,
        2,
        1,
        200,
        2,
        1,
        128,
        1,
        HElibKnownAnswerTest<DASTA_128_HElib>::Testcase::DEC,
    },
    {
        {0x76, 0xad, 0x7b, 0x3f, 0x23, 0xe9, 0x58, 0x09, 0x47, 0x7c, 0xb8,
         0x14, 0xcc, 0x35, 0xec, 0x1e, 0xa6, 0x1e, 0xba, 0xfe, 0x80, 0x43,
         0x22, 0x62, 0x87, 0x65, 0x59, 0x58, 0x56, 0x2e, 0x6c, 0x98, 0x6e,
         0x45, 0xdc, 0xed, 0x34, 0x43, 0x0d, 0xc7, 0x87, 0x13, 0x0c, 0x04,
         0x73, 0x91, 0xbd, 0xfe, 0x34, 0x17, 0x4c, 0xee, 0xc7, 0x44, 0x85,
         0x99, 0xe2, 0x14, 0xe1, 0x55, 0xd3, 0x70, 0x14, 0xa4, 0xdb, 0x20},
        {0x00},
        {0x00},
        0,
        2,
        1,
        570,
        2,
        1,
        128,
        1,
        HElibKnownAnswerTest<DASTA_128_HElib>::Testcase::USE_CASE,
        5,
        16,
    }};
