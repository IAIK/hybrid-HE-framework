#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <iterator>
#include <vector>

extern "C" {
#include "perf.h"
}

#include "Cipher.h"
#include "matrix.h"
#include "utils.h"

template <class T>
class KnownAnswerTest {
 public:
  enum Testcase { MAT, DEC, USE_CASE, PREP };

 private:
  static constexpr bool PRESET_SEED = true;
  utils::SeededRandom rand;
  std::vector<uint8_t> key;
  std::vector<uint8_t> plaintext;
  std::vector<uint8_t> ciphertext_expected;
  Testcase tc;
  size_t N;
  size_t BITSIZE;

 public:
  KnownAnswerTest(std::vector<uint8_t> key, std::vector<uint8_t> plaintext,
                  std::vector<uint8_t> ciphertext_expected, Testcase tc = DEC,
                  size_t N = 4, size_t bitsize = 16)
      : rand(PRESET_SEED),
        key(key),
        plaintext(plaintext),
        ciphertext_expected(ciphertext_expected),
        tc(tc),
        N(N),
        BITSIZE(bitsize) {}

  KnownAnswerTest(const uint8_t* key, size_t key_size, const uint8_t* plaintext,
                  size_t plaintext_size, const uint8_t* ciphertext_expected,
                  size_t ciphertext_size, Testcase tc = DEC, size_t N = 4,
                  size_t bitsize = 16)
      : rand(PRESET_SEED),
        key(key, key + key_size),
        plaintext(plaintext, plaintext + plaintext_size),
        ciphertext_expected(ciphertext_expected,
                            ciphertext_expected + ciphertext_size),
        tc(tc),
        N(N),
        BITSIZE(bitsize) {}

  bool mat_test() {
    const uint64_t MASK = (1ULL << BITSIZE) - 1;
    std::cout << "N = " << N << std::endl;
    std::cout << "BitSize = " << BITSIZE << std::endl;
    std::cout << "Getting random elements..." << std::flush;

    // random matrix
    matrix::matrix m(N);
    for (size_t i = 0; i < N; i++) {
      m[i].reserve(N);
      for (size_t j = 0; j < N; j++) {
        m[i].push_back(rand.random_uint64() & MASK);
      }
    }

    // random bias
    matrix::vector b;
    b.reserve(N);
    for (size_t i = 0; i < N; i++) {
      b.push_back(rand.random_uint64() & MASK);
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() & MASK);
    }

    std::cout << "...done" << std::endl;
    std::cout << "Computing in plain..." << std::flush;

    matrix::vector vo;
    matrix::affine(vo, m, vi, b, BITSIZE);

    std::cout << "...done" << std::endl;
    return true;
  }

  bool dec_test() {
    timing_context_t ctx;
    if (!timing_init(&ctx)) {
      std::cerr << "Failed to init timing context" << std::endl;
      return false;
    }
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::milliseconds time_diff;

    T cipher(key);
    std::cout << "Final decrypt..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    uint64_t cycle_start = timing_read(&ctx);
    std::vector<uint8_t> plain =
        cipher.decrypt(ciphertext_expected, cipher.get_cipher_size_bits());
    uint64_t cycle_end = timing_read(&ctx);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "Cycles: " << cycle_end - cycle_start << std::endl;

    timing_close(&ctx);

    if (plain != plaintext) {
      std::cerr << cipher.get_cipher_name() << " KATS failed!\n";
      utils::print_vector("key:      ", key, std::cerr);
      utils::print_vector("ciphertext", ciphertext_expected, std::cerr);
      utils::print_vector("plain:    ", plaintext, std::cerr);
      utils::print_vector("got:      ", plain, std::cerr);
      return false;
    }
    return true;
  }

  bool test() {
    timing_context_t ctx;
    if (!timing_init(&ctx)) {
      std::cerr << "Failed to init timing context" << std::endl;
      return false;
    }
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::milliseconds time_diff;

    const uint64_t MASK = (1ULL << BITSIZE) - 1;
    std::cout << "N = " << N << std::endl;
    std::cout << "BitSize = " << BITSIZE << std::endl;
    std::cout << "Getting random elements..." << std::flush;

    // random matrix
    matrix::matrix m(N);
    for (size_t i = 0; i < N; i++) {
      m[i].reserve(N);
      for (size_t j = 0; j < N; j++) {
        m[i].push_back(rand.random_uint64() & MASK);
      }
    }

    // random bias
    matrix::vector b;
    b.reserve(N);
    for (size_t i = 0; i < N; i++) {
      b.push_back(rand.random_uint64() & MASK);
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() & MASK);
    }

    std::cout << "...done" << std::endl;

    std::cout << "Computing in plain..." << std::flush;

    matrix::vector vo, vo_p(N);
    time_start = std::chrono::high_resolution_clock::now();
    uint64_t cycle_start = timing_read(&ctx);
    matrix::affine(vo, m, vi, b, BITSIZE);
    uint64_t cycle_end = timing_read(&ctx);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "Cycles: " << cycle_end - cycle_start << std::endl;

    std::cout << "Encrypting input..." << std::flush;
    T cipher(key);
    std::vector<uint8_t> vi_encoded;
    utils::encode(vi_encoded, vi, BITSIZE);
    time_start = std::chrono::high_resolution_clock::now();
    cycle_start = timing_read(&ctx);
    std::vector<uint8_t> ciph = cipher.encrypt(vi_encoded, BITSIZE * N);
    cycle_end = timing_read(&ctx);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "Cycles: " << cycle_end - cycle_start << std::endl;

    std::cout << "Decrypting..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    cycle_start = timing_read(&ctx);
    std::vector<uint8_t> plain_encoded = cipher.decrypt(ciph, BITSIZE * N);
    cycle_end = timing_read(&ctx);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    matrix::vector plain;
    utils::decode(plain, plain_encoded, BITSIZE);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "Cycles: " << cycle_end - cycle_start << std::endl;

    std::cout << "Computing..." << std::flush;

    time_start = std::chrono::high_resolution_clock::now();
    cycle_start = timing_read(&ctx);
    matrix::affine(vo_p, m, plain, b, BITSIZE);
    cycle_end = timing_read(&ctx);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "Cycles: " << cycle_end - cycle_start << std::endl;

    if (vo != vo_p) {
      std::cerr << cipher.get_cipher_name() << " KATS failed!\n";
      utils::print_vector("plain:  ", vo, std::cerr);
      utils::print_vector("cipher: ", vo_p, std::cerr);
      return false;
    }
    return true;
  }

  bool prep_test() {
    timing_context_t ctx;
    if (!timing_init(&ctx)) {
      std::cerr << "Failed to init timing context" << std::endl;
      return false;
    }
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::milliseconds time_diff;

    T cipher(key);
    std::cout << "Preprocessing constants for 1 block..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    uint64_t cycle_start = timing_read(&ctx);
    cipher.prep_one_block();
    uint64_t cycle_end = timing_read(&ctx);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "Cycles: " << cycle_end - cycle_start << std::endl;

    timing_close(&ctx);
    return true;
  }

  virtual bool run_test() {
    switch (tc) {
      case MAT:
        return mat_test();
      case DEC:
        return dec_test();
      case USE_CASE:
        return test();
      case PREP:
        return prep_test();
      default: {
        std::cout << "Testcase not found... " << std::endl;
        return false;
      }
    }
  }
};
