#pragma once

#include "../../common/helib_kats.h"
#include "kreyvium_helib.h"

using namespace KREYVIUM;

// build an array of KnownAnswerTests for KREYVIUM
HElibKnownAnswerTest<KREYVIUM_HElib> KNOWN_ANSWER_TESTS[] = {
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
        HElibKnownAnswerTest<KREYVIUM_HElib>::Testcase::DEC,
    },
    {
        {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
         0x55, 0x55, 0x55, 0x55},
        {0x00},
        {0x00},
        0,
        2,
        1,
        670,
        2,
        1,
        128,
        1,
        HElibKnownAnswerTest<KREYVIUM_HElib>::Testcase::USE_CASE,
        5,
        16,
    }};
