#pragma once

#include "../../common/tfhe_kats.h"
#include "rasta_5_tfhe.h"

using namespace RASTA_5;

// build an array of KnownAnswerTests for RASTA_128
TFHEKnownAnswerTest<RASTA_128_TFHE> KNOWN_ANSWER_TESTS[] = {
    {
        {0x76, 0xad, 0x7b, 0x3f, 0x23, 0xe9, 0x58, 0x09, 0x47, 0x7c, 0xb8,
         0x14, 0xcc, 0x35, 0xec, 0x1e, 0xa6, 0x1e, 0xba, 0xfe, 0x80, 0x43,
         0x22, 0x62, 0x87, 0x65, 0x59, 0x58, 0x56, 0x2e, 0x6c, 0x98, 0x6e,
         0x45, 0xdc, 0xed, 0x34, 0x43, 0x0d, 0xc7, 0x87, 0x13, 0x0c, 0x04,
         0x73, 0x91, 0xbd, 0xfe, 0x34, 0x17, 0x4c, 0xee, 0xc7, 0x44, 0x85,
         0x99, 0xe2, 0x14, 0xe1, 0x55, 0xd3, 0x70, 0x14, 0xa4, 0xdb, 0x20},
        {0x84, 0x35, 0xd9, 0x7c, 0x41, 0x20, 0xc0, 0x4f, 0xcf, 0xf1, 0x6a,
         0x94, 0x1e, 0xbd, 0x5c, 0xf7, 0xe8, 0xe7, 0x48, 0x85, 0xd9, 0x33,
         0xf4, 0xdb, 0x97, 0x0a, 0xc4, 0x38, 0x54, 0x84, 0x7a, 0xcf, 0xeb,
         0xc9, 0x00, 0x33, 0xec, 0xf2, 0xf4, 0xba, 0x5f, 0x1f, 0xbf, 0xf0,
         0x10, 0x35, 0x20, 0x00, 0xa0, 0x85, 0x69, 0xea, 0x40, 0xad, 0x82,
         0x91, 0x14, 0x59, 0xce, 0xb2, 0xf9, 0x17, 0xd3, 0xcc, 0x79, 0x18},
        {0xbf, 0x5f, 0x03, 0x4c, 0x26, 0x3b, 0xbd, 0xd4, 0x0c, 0xc0, 0x6e,
         0xd3, 0x81, 0xa4, 0x59, 0xde, 0xec, 0xd3, 0xd8, 0xdb, 0xb6, 0x71,
         0xc3, 0xa1, 0xde, 0x3d, 0x13, 0x4b, 0x84, 0x28, 0x51, 0x43, 0x0c,
         0x71, 0x9a, 0x7c, 0x01, 0x97, 0x9f, 0x26, 0x84, 0xfb, 0x9d, 0x90,
         0xf6, 0x1d, 0x64, 0xab, 0x12, 0x3f, 0x66, 0xc8, 0xde, 0xa1, 0xde,
         0xb5, 0xc9, 0x30, 0x24, 0xb6, 0xcd, 0xda, 0x15, 0x2b, 0x0a, 0x60},
        128,
        TFHEKnownAnswerTest<RASTA_128_TFHE>::Testcase::DEC,
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
        128,
        TFHEKnownAnswerTest<RASTA_128_TFHE>::Testcase::USE_CASE,
        5,
        16,
    }};
