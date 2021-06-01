#pragma once

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <random>
#include <vector>
#ifdef _WIN32
#include <Windows.h>
#include <bcrypt.h>
#endif

extern "C" {
#include "KeccakHash.h"
}

namespace utils {
static void print_vector(std::string info, std::vector<uint8_t> vec,
                         std::ostream& out) {
  std::ios_base::fmtflags f(out.flags());  // get flags
  if (!info.empty()) {
    out << info << " ";
  }
  out << "{";
  const auto delim = ", ";
  for (auto a : vec) {
    out << std::hex << std::setw(2) << std::setfill('0');
    out << int(a) << delim;
  }
  out << "}\n";

  out.flags(f);  // reset flags
}

static void print_vector(std::string info, std::vector<uint64_t> vec,
                         std::ostream& out) {
  std::ios_base::fmtflags f(out.flags());  // get flags
  if (!info.empty()) {
    out << info << " ";
  }
  out << "{";
  const auto delim = ", ";
  for (auto a : vec) {
    out << std::hex << std::setw(16) << std::setfill('0');
    out << a << delim;
  }
  out << "}\n";

  out.flags(f);  // reset flags
}

static void encode(std::vector<uint8_t>& encoded, std::vector<uint64_t> in,
                   size_t bitsize) {
  size_t size = in.size() * bitsize;
  size = ceil((double)size / 8.0);

  encoded.clear();
  encoded.reserve(size);

  uint8_t tmp = 0;
  uint8_t cnt = 0;
  for (size_t i = 0; i < in.size(); i++) {
    for (size_t k = 0; k < bitsize; k++) {
      uint8_t bit = (in[i] >> k) & 1;
      tmp |= (bit << (7 - cnt));
      cnt++;
      if (cnt == 8) {
        encoded.push_back(tmp);
        cnt = 0;
        tmp = 0;
      }
    }
  }
  if (cnt) encoded.push_back(tmp);
}

static void decode(std::vector<uint64_t>& out, std::vector<uint8_t> encoded,
                   size_t bitsize) {
  size_t size = encoded.size() * 8;
  size /= bitsize;
  out.clear();
  out.reserve(size);

  uint64_t tmp = 0;
  uint8_t cnt = 0;
  for (size_t i = 0; i < encoded.size(); i++) {
    for (size_t k = 0; k < 8; k++) {
      uint8_t bit = (encoded[i] >> (7 - k)) & 1;
      tmp |= (bit << cnt);
      cnt++;
      if (cnt == bitsize) {
        out.push_back(tmp);
        tmp = 0;
        cnt = 0;
      }
    }
  }
}

// random_uint64() taken from the SEAL library
// (https://github.com/microsoft/SEAL)
static uint64_t random_uint64() {
  uint64_t result;
#ifdef __linux__
  std::random_device rd("/dev/urandom");
  result = (static_cast<uint64_t>(rd()) << 32) + static_cast<uint64_t>(rd());
#elif _WIN32
  if (!BCRYPT_SUCCESS(
          BCryptGenRandom(NULL, reinterpret_cast<unsigned char*>(&result),
                          sizeof(result), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
    throw runtime_error("BCryptGenRandom failed");
  }
#else
#warning \
    "SECURITY WARNING: System detection failed; falling back to a potentially insecure randomness source!"
  random_device rd;
  result = (static_cast<uint64_t>(rd()) << 32) + static_cast<uint64_t>(rd());
#endif
  return result;
}

class SeededRandom {
 private:
  Keccak_HashInstance shake128_;

  void init_shake(std::array<uint8_t, 16>& seed) {
    if (SUCCESS != Keccak_HashInitialize_SHAKE128(&shake128_))
      throw std::runtime_error("failed to init shake");
    if (SUCCESS != Keccak_HashUpdate(&shake128_, seed.data(), seed.size() * 8))
      throw std::runtime_error("SHAKE128 update failed");
    if (SUCCESS != Keccak_HashFinal(&shake128_, NULL))
      throw std::runtime_error("SHAKE128 final failed");
  }

  void init_shake(uint64_t seed1, uint64_t seed2) {
    std::array<uint8_t, 16> seed;
    uint8_t* seed_data = seed.data();
    *((uint64_t*)seed_data) = htobe64(seed1);
    *((uint64_t*)(seed_data + 8)) = htobe64(seed2);
    init_shake(seed);
  }

 public:
  static constexpr uint64_t PRESET_SEED1 = 5414582108744027571ULL;
  static constexpr uint64_t PRESET_SEED2 = 3580691526476218256ULL;

  SeededRandom(bool preset_seed = false) {
    if (preset_seed)
      init_shake(PRESET_SEED1, PRESET_SEED2);
    else
      init_shake(utils::random_uint64(), utils::random_uint64());
  }

  SeededRandom(uint64_t seed1, uint64_t seed2) { init_shake(seed1, seed2); }

  SeededRandom(std::array<uint8_t, 16>& seed) { init_shake(seed); }

  ~SeededRandom() = default;
  SeededRandom(const SeededRandom&) = delete;
  SeededRandom& operator=(const SeededRandom&) = delete;
  SeededRandom(const SeededRandom&&) = delete;

  uint64_t random_uint64() {
    uint8_t random_bytes[sizeof(uint64_t)];
    if (SUCCESS !=
        Keccak_HashSqueeze(&shake128_, random_bytes, sizeof(random_bytes) * 8))
      throw std::runtime_error("SHAKE128 squeeze failed");
    return be64toh(*((uint64_t*)random_bytes));
  };
};

}  // namespace utils
