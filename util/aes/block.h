#pragma once

#include <array>
#include <cstdint>
#include <iostream>

#ifdef OC_ENABLE_SSE2
#include <emmintrin.h>
#include <smmintrin.h>
#else
#ifdef OC_ENABLE_AESNI
#include <wmmintrin.h>
#endif
#endif

namespace osuCrypto {
struct alignas(16) block {
#if defined(OC_ENABLE_SSE2) || defined(OC_ENABLE_AESNI)
  __m128i mData;
#else
  std::uint64_t mData[2];
#endif

  block() = default;
  block(const block&) = default;
  block(uint64_t x1, uint64_t x0) {
#ifdef OC_ENABLE_SSE2
    mData = _mm_set_epi64x(x1, x0);
#else
    as<uint64_t>()[0] = x0;
    as<uint64_t>()[1] = x1;
#endif
  };

  block(char e15, char e14, char e13, char e12, char e11, char e10, char e9,
        char e8, char e7, char e6, char e5, char e4, char e3, char e2, char e1,
        char e0) {
#ifdef OC_ENABLE_SSE2
    mData = _mm_set_epi8(e15, e14, e13, e12, e11, e10, e9, e8, e7, e6, e5, e4,
                         e3, e2, e1, e0);
#else
    as<char>()[0] = e0;
    as<char>()[1] = e1;
    as<char>()[2] = e2;
    as<char>()[3] = e3;
    as<char>()[4] = e4;
    as<char>()[5] = e5;
    as<char>()[6] = e6;
    as<char>()[7] = e7;
    as<char>()[8] = e8;
    as<char>()[9] = e9;
    as<char>()[10] = e10;
    as<char>()[11] = e11;
    as<char>()[12] = e12;
    as<char>()[13] = e13;
    as<char>()[14] = e14;
    as<char>()[15] = e15;
#endif
  }

#if defined(OC_ENABLE_SSE2) || defined(OC_ENABLE_AESNI)
  block(const __m128i& x) { mData = x; }

  operator const __m128i&() const { return mData; }
  operator __m128i&() { return mData; }

  __m128i& m128i() { return mData; }
  const __m128i& m128i() const { return mData; }
#endif
  template <typename T>
  typename std::enable_if<std::is_pod<T>::value && (sizeof(T) <= 16) &&
                              (16 % sizeof(T) == 0),
                          std::array<T, 16 / sizeof(T)>&>::type
  as() {
    return *(std::array<T, 16 / sizeof(T)>*)this;
  }

  template <typename T>
  typename std::enable_if<std::is_pod<T>::value && (sizeof(T) <= 16) &&
                              (16 % sizeof(T) == 0),
                          const std::array<T, 16 / sizeof(T)>&>::type
  as() const {
    return *(const std::array<T, 16 / sizeof(T)>*)this;
  }

  inline bool operator<(const osuCrypto::block& rhs) {
    auto& x = as<std::uint64_t>();
    auto& y = rhs.as<std::uint64_t>();
    return x[1] < y[1] || (x[1] == y[1] && x[0] < y[0]);
  }

  inline osuCrypto::block operator^(const osuCrypto::block& rhs) const {
#ifdef OC_ENABLE_SSE2
    return mm_xor_si128(rhs);
#else
    return cc_xor_si128(rhs);
#endif
  }
#ifdef OC_ENABLE_SSE2
  inline osuCrypto::block mm_xor_si128(const osuCrypto::block& rhs) const {
    return _mm_xor_si128(*this, rhs);
  }
#endif
  inline osuCrypto::block cc_xor_si128(const osuCrypto::block& rhs) const {
    auto ret = *this;
    ret.as<std::uint64_t>()[0] ^= rhs.as<std::uint64_t>()[0];
    ret.as<std::uint64_t>()[1] ^= rhs.as<std::uint64_t>()[1];
    return ret;
  }

  inline osuCrypto::block operator&(const osuCrypto::block& rhs) const {
#ifdef OC_ENABLE_SSE2
    return mm_and_si128(rhs);
#else
    return cc_and_si128(rhs);
#endif
  }

#ifdef OC_ENABLE_SSE2
  inline osuCrypto::block mm_and_si128(const osuCrypto::block& rhs) const {
    return _mm_and_si128(*this, rhs);
  }
#endif
  inline osuCrypto::block cc_and_si128(const osuCrypto::block& rhs) const {
    auto ret = *this;
    ret.as<std::uint64_t>()[0] &= rhs.as<std::uint64_t>()[0];
    ret.as<std::uint64_t>()[1] &= rhs.as<std::uint64_t>()[1];
    return ret;
  }

  inline osuCrypto::block operator|(const osuCrypto::block& rhs) const {
#ifdef OC_ENABLE_SSE2
    return mm_or_si128(rhs);
#else
    return cc_or_si128(rhs);
#endif
  }
#ifdef OC_ENABLE_SSE2
  inline osuCrypto::block mm_or_si128(const osuCrypto::block& rhs) const {
    return _mm_or_si128(*this, rhs);
  }
#endif
  inline osuCrypto::block cc_or_si128(const osuCrypto::block& rhs) const {
    auto ret = *this;
    ret.as<std::uint64_t>()[0] |= rhs.as<std::uint64_t>()[0];
    ret.as<std::uint64_t>()[1] |= rhs.as<std::uint64_t>()[1];
    return ret;
  }

  inline osuCrypto::block operator<<(const std::uint8_t& rhs) const {
#ifdef OC_ENABLE_SSE2
    return mm_slli_epi64(rhs);
#else
    return cc_slli_epi64(rhs);
#endif
  }

#ifdef OC_ENABLE_SSE2
  inline osuCrypto::block mm_slli_epi64(const std::uint8_t& rhs) const {
    return _mm_slli_epi64(*this, rhs);
  }
#endif
  inline osuCrypto::block cc_slli_epi64(const std::uint8_t& rhs) const {
    auto ret = *this;
    ret.as<std::uint64_t>()[0] <<= rhs;
    ret.as<std::uint64_t>()[1] <<= rhs;
    return ret;
  }

  inline block operator>>(const std::uint8_t& rhs) const {
#ifdef OC_ENABLE_SSE2
    return mm_srli_epi64(rhs);
#else
    return cc_srli_epi64(rhs);
#endif
  }

#ifdef OC_ENABLE_SSE2
  inline block mm_srli_epi64(const std::uint8_t& rhs) const {
    return _mm_srli_epi64(*this, rhs);
  }
#endif
  inline block cc_srli_epi64(const std::uint8_t& rhs) const {
    auto ret = *this;
    ret.as<std::uint64_t>()[0] >>= rhs;
    ret.as<std::uint64_t>()[1] >>= rhs;
    return ret;
    ;
  }

  inline osuCrypto::block operator+(const osuCrypto::block& rhs) const {
#ifdef OC_ENABLE_SSE2
    return mm_add_epi64(rhs);
#else
    return cc_add_epi64(rhs);
#endif
  }

#ifdef OC_ENABLE_SSE2
  inline block mm_add_epi64(const osuCrypto::block& rhs) const {
    return _mm_add_epi64(*this, rhs);
  }
#endif
  inline block cc_add_epi64(const osuCrypto::block& rhs) const {
    auto ret = *this;
    ret.as<std::uint64_t>()[0] += rhs.as<std::uint64_t>()[0];
    ret.as<std::uint64_t>()[1] += rhs.as<std::uint64_t>()[1];
    return ret;
  }

  inline osuCrypto::block operator-(const osuCrypto::block& rhs) const {
#ifdef OC_ENABLE_SSE2
    return mm_sub_epi64(rhs);
#else
    return cc_sub_epi64(rhs);
#endif
  }

#ifdef OC_ENABLE_SSE2
  inline block mm_sub_epi64(const osuCrypto::block& rhs) const {
    return _mm_sub_epi64(*this, rhs);
  }
#endif
  inline block cc_sub_epi64(const osuCrypto::block& rhs) const {
    auto ret = *this;
    ret.as<std::uint64_t>()[0] -= rhs.as<std::uint64_t>()[0];
    ret.as<std::uint64_t>()[1] -= rhs.as<std::uint64_t>()[1];
    return ret;
  }

  inline bool operator==(const osuCrypto::block& rhs) const {
#ifdef OC_ENABLE_SSE2
    auto neq = _mm_xor_si128(*this, rhs);
    return _mm_test_all_zeros(neq, neq) != 0;
#else
    return as<std::uint64_t>()[0] == rhs.as<std::uint64_t>()[0] &&
           as<std::uint64_t>()[1] == rhs.as<std::uint64_t>()[1];
#endif
  }

  inline bool operator!=(const osuCrypto::block& rhs) const {
    return !(*this == rhs);
  }

  inline block srai_epi16(int imm8) const {
#ifdef OC_ENABLE_SSE2
    return mm_srai_epi16(imm8);
#else
    return cc_srai_epi16(imm8);
#endif
  }

#ifdef OC_ENABLE_SSE2
  inline block mm_srai_epi16(char imm8) const {
    return _mm_srai_epi16(*this, imm8);
  }
#endif
  inline block cc_srai_epi16(char imm8) const {
    block ret;
    auto& v = as<std::int16_t>();
    auto& r = ret.as<std::int16_t>();
    if (imm8 <= 15) {
      r[0] = v[0] >> imm8;
      r[1] = v[1] >> imm8;
      r[2] = v[2] >> imm8;
      r[3] = v[3] >> imm8;
      r[4] = v[4] >> imm8;
      r[5] = v[5] >> imm8;
      r[6] = v[6] >> imm8;
      r[7] = v[7] >> imm8;
    } else {
      r[0] = v[0] ? 0xFFFF : 0;
      r[1] = v[1] ? 0xFFFF : 0;
      r[2] = v[2] ? 0xFFFF : 0;
      r[3] = v[3] ? 0xFFFF : 0;
      r[4] = v[4] ? 0xFFFF : 0;
      r[5] = v[5] ? 0xFFFF : 0;
      r[6] = v[6] ? 0xFFFF : 0;
      r[7] = v[7] ? 0xFFFF : 0;
    }
    return ret;
  }

  inline int movemask_epi8() const {
#ifdef OC_ENABLE_SSE2
    return mm_movemask_epi8();
#else
    return cc_movemask_epi8();
#endif
  }

#ifdef OC_ENABLE_SSE2
  inline int mm_movemask_epi8() const { return _mm_movemask_epi8(*this); }
#endif

  inline int cc_movemask_epi8() const {
    int ret{0};
    auto& v = as<unsigned char>();
    int j = 0;
    for (int i = 7; i >= 0; --i) ret |= std::uint16_t(v[j++] & 128) >> i;

    for (size_t i = 1; i <= 8; i++) ret |= std::uint16_t(v[j++] & 128) << i;

    return ret;
  }
};

static_assert(sizeof(block) == 16, "expected block size");
static_assert(std::alignment_of<block>::value == 16,
              "expected block alignment");
static_assert(std::is_trivial<block>::value, "expected block trivial");
static_assert(std::is_standard_layout<block>::value, "expected block pod");
//#define _SILENCE_ALL_CXX20_DEPRECATION_WARNINGS
// static_assert(std::is_pod<block>::value, "expected block pod");

inline block toBlock(std::uint64_t high_u64, std::uint64_t low_u64) {
  block ret;
  ret.as<std::uint64_t>()[0] = low_u64;
  ret.as<std::uint64_t>()[1] = high_u64;
  return ret;
}
inline block toBlock(std::uint64_t low_u64) { return toBlock(0, low_u64); }
inline block toBlock(const std::uint8_t* data) {
  return toBlock(((std::uint64_t*)data)[1], ((std::uint64_t*)data)[0]);
}

extern const block ZeroBlock;
extern const block OneBlock;
extern const block AllOneBlock;
extern const block CCBlock;
extern const std::array<block, 2> zeroAndAllOne;
}  // namespace osuCrypto

std::ostream& operator<<(std::ostream& out, const osuCrypto::block& block);
namespace osuCrypto {
using ::operator<<;
}

inline bool eq(const osuCrypto::block& lhs, const osuCrypto::block& rhs) {
  return lhs == rhs;
}

inline bool neq(const osuCrypto::block& lhs, const osuCrypto::block& rhs) {
  return lhs != rhs;
}
