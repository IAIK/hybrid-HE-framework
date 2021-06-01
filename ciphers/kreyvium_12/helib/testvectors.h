#pragma once

#include "../../common/helib_kats.h"
#include "kreyvium_12_helib.h"

using namespace KREYVIUM_12;

// build an array of KnownAnswerTests for KREYVIUM_12
HElibKnownAnswerTest<KREYVIUM12_HElib> KNOWN_ANSWER_TESTS[] = {
    {
        {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
         0x55, 0x55, 0x55, 0x55},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x89, 0xA3, 0xB7, 0x00, 0xD9, 0x44},
        0,
        2,
        1,
        250,
        2,
        1,
        128,
        1,
        HElibKnownAnswerTest<KREYVIUM12_HElib>::Testcase::DEC,
    },
    {
        {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
         0x55, 0x55, 0x55, 0x55},
        {0x00},
        {0x00},
        0,
        2,
        1,
        660,
        2,
        1,
        128,
        1,
        HElibKnownAnswerTest<KREYVIUM12_HElib>::Testcase::USE_CASE,
        5,
        16,
    }};
