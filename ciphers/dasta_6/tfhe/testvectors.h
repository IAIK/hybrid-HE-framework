#pragma once

#include "../../common/tfhe_kats.h"
#include "dasta_6_tfhe.h"

using namespace DASTA_6;

// build an array of KnownAnswerTests for DASTA_128
TFHEKnownAnswerTest<DASTA_128_TFHE> KNOWN_ANSWER_TESTS[] = {
    {
        {0x76, 0xad, 0x7b, 0x3f, 0x23, 0xe9, 0x58, 0x09, 0x47, 0x7c, 0xb8,
         0x14, 0xcc, 0x35, 0xec, 0x1e, 0xa6, 0x1e, 0xba, 0xfe, 0x80, 0x43,
         0x22, 0x62, 0x87, 0x65, 0x59, 0x58, 0x56, 0x2e, 0x6c, 0x98, 0x6e,
         0x45, 0xdc, 0xed, 0x34, 0x43, 0x0d, 0xc7, 0x87, 0x13, 0x0c, 0x04},
        {0x84, 0x35, 0xd9, 0x7c, 0x41, 0x20, 0xc0, 0x4f, 0xcf, 0xf1, 0x6a,
         0x94, 0x1e, 0xbd, 0x5c, 0xf7, 0xe8, 0xe7, 0x48, 0x85, 0xd9, 0x33,
         0xf4, 0xdb, 0x97, 0x0a, 0xc4, 0x38, 0x54, 0x84, 0x7a, 0xcf, 0xeb,
         0xc9, 0x00, 0x33, 0xec, 0xf2, 0xf4, 0xba, 0x5f, 0x1f, 0xbf, 0xf0},
        {0x99, 0xa5, 0xf7, 0xce, 0xe0, 0x99, 0x69, 0x9a, 0x03, 0x48, 0x0b,
         0x45, 0xb5, 0x83, 0x60, 0x41, 0x1f, 0xcf, 0x8a, 0x19, 0x90, 0xd6,
         0x8a, 0x06, 0x8b, 0x78, 0x5d, 0xdd, 0xbe, 0xcf, 0x56, 0x55, 0x1d,
         0xc7, 0xc4, 0xdf, 0xb5, 0x87, 0x6a, 0xf8, 0x9b, 0xd1, 0xed, 0x5c},
        128,
        TFHEKnownAnswerTest<DASTA_128_TFHE>::Testcase::DEC,
    },
    {
        {0x76, 0xad, 0x7b, 0x3f, 0x23, 0xe9, 0x58, 0x09, 0x47, 0x7c, 0xb8,
         0x14, 0xcc, 0x35, 0xec, 0x1e, 0xa6, 0x1e, 0xba, 0xfe, 0x80, 0x43,
         0x22, 0x62, 0x87, 0x65, 0x59, 0x58, 0x56, 0x2e, 0x6c, 0x98, 0x6e,
         0x45, 0xdc, 0xed, 0x34, 0x43, 0x0d, 0xc7, 0x87, 0x13, 0x0c, 0x04},
        {0x00},
        {0x00},
        128,
        TFHEKnownAnswerTest<DASTA_128_TFHE>::Testcase::USE_CASE,
        5,
        16,
    }};
