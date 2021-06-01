#pragma once

#include "helib/helib.h"
#include "matrix.h"
#include "utils.h"

template <class T>
class HElibKnownAnswerTest {
 public:
  enum Testcase { MAT, DEC, USE_CASE };

 private:
  static constexpr bool PRESET_SEED = true;
  utils::SeededRandom rand;
  std::vector<uint8_t> key;
  std::vector<uint8_t> plaintext;
  std::vector<uint8_t> ciphertext_expected;
  long m;  // m-th cyclotomic polynomial
  long p;  // plaintext prime
  long r;  // Lifting [defualt = 1]
  long L;  // bits in the ciphertext modulus chain
  long c;  // columns in the key-switching matrix [default=2]
  long d;  // Degree of the field extension [default=1]
  long k;  // Security parameter [default=80]
  long s;  // Minimum number of slots [default=0]
  Testcase tc;
  size_t N;
  size_t BITSIZE;
  bool use_bsgs;

 public:
  HElibKnownAnswerTest(std::vector<uint8_t> key, std::vector<uint8_t> plaintext,
                       std::vector<uint8_t> ciphertext_expected, long m, long p,
                       long r, long L, long c, long d = 1, long k = 128,
                       long s = 1, Testcase tc = DEC, size_t N = 4,
                       size_t bitsize = 16, bool use_bsgs = false)
      : rand(PRESET_SEED),
        key(key),
        plaintext(plaintext),
        ciphertext_expected(ciphertext_expected),
        m(m),
        p(p),
        r(r),
        L(L),
        c(c),
        d(d),
        k(k),
        s(s),
        tc(tc),
        N(N),
        BITSIZE(bitsize),
        use_bsgs(use_bsgs) {}

  HElibKnownAnswerTest(const uint8_t* key, size_t key_size,
                       const uint8_t* plaintext, size_t plaintext_size,
                       const uint8_t* ciphertext_expected,
                       size_t ciphertext_size, long m, long p, long r, long L,
                       long c, long d = 1, long k = 128, long s = 1,
                       Testcase tc = DEC, size_t N = 4, size_t bitsize = 16,
                       bool use_bsgs = false)
      : rand(PRESET_SEED),
        key(key, key + key_size),
        plaintext(plaintext, plaintext + plaintext_size),
        ciphertext_expected(ciphertext_expected,
                            ciphertext_expected + ciphertext_size),
        m(m),
        p(p),
        r(r),
        L(L),
        c(c),
        d(d),
        k(k),
        s(s),
        tc(tc),
        N(N),
        BITSIZE(bitsize),
        use_bsgs(use_bsgs) {}

  bool mat_test() {
    auto context = T::create_context(m, p, r, L, c, d, k, s);
    T cipher(key, context, L, c);
    cipher.print_parameters();
    const uint64_t MASK = (1ULL << BITSIZE) - 1;
    std::cout << "N = " << N << std::endl;
    std::cout << "BitSize = " << BITSIZE << std::endl;
    std::cout << "Getting random elements..." << std::flush;

    // random matrix
    matrix::matrix mat(N);
    for (size_t i = 0; i < N; i++) {
      mat[i].reserve(N);
      for (size_t j = 0; j < N; j++) {
        mat[i].push_back(rand.random_uint64() & MASK);
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
    matrix::affine(vo, mat, vi, b, BITSIZE);

    std::cout << "...done" << std::endl;
    std::cout << "Computing in HE..." << std::endl;

    // HE:
    typename T::e_vector vi_e(N);
    typename T::e_vector vo_e;
    for (size_t i = 0; i < N; i++) {
      cipher.encrypt(vi_e[i], vi[i], BITSIZE);
    }
    std::cout << "initial noise:" << std::endl;
    cipher.print_noise(vi_e[0]);

    cipher.affine(vo_e, mat, vi_e, b);

    std::cout << "final noise:" << std::endl;
    cipher.print_noise(vo_e[0]);

    for (size_t i = 0; i < N; i++) {
      cipher.decrypt(vo_e[i], vo_p[i]);
    }

    std::cout << "...done" << std::endl;
    if (vo != vo_p) {
      std::cerr << cipher.get_cipher_name() << " KATS failed!\n";
      utils::print_vector("plain:  ", vo, std::cerr);
      utils::print_vector("cipher: ", vo_p, std::cerr);
      return false;
    }
    return true;
  }

  bool dec_test() {
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::milliseconds time_diff;

    auto context = T::create_context(m, p, r, L, c, d, k, s);
    T cipher(key, context, L, c);
    cipher.print_parameters();
    cipher.activate_bsgs(use_bsgs);

    std::cout << "HE encrypting key..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    cipher.encrypt_key();
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

    std::cout << "initial noise:" << std::endl;
    cipher.print_noise();

    std::cout << "HE decrypting..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    std::vector<helib::Ctxt> ciph =
        cipher.HE_decrypt(ciphertext_expected, cipher.get_cipher_size_bits());
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

    std::cout << "final noise:" << std::endl;
    cipher.print_noise(ciph);

    std::cout << "Final decrypt..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> plain = cipher.decrypt_result(ciph);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

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
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::milliseconds time_diff;

    const uint64_t MASK = (1ULL << BITSIZE) - 1;
    std::cout << "N = " << N << std::endl;
    std::cout << "BitSize = " << BITSIZE << std::endl;
    std::cout << "Getting random elements..." << std::flush;

    // random matrix
    matrix::matrix mat(N);
    for (size_t i = 0; i < N; i++) {
      mat[i].reserve(N);
      for (size_t j = 0; j < N; j++) {
        mat[i].push_back(rand.random_uint64() & MASK);
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
    matrix::affine(vo, mat, vi, b, BITSIZE);

    std::cout << "...done" << std::endl;

    std::cout << "Encrypting input..." << std::flush;
    typename T::Plain plain_cipher(key);
    std::vector<uint8_t> vi_encoded;
    utils::encode(vi_encoded, vi, BITSIZE);
    time_start = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> ciph = plain_cipher.encrypt(vi_encoded, BITSIZE * N);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

    auto context = T::create_context(m, p, r, L, c, d, k, s);
    T cipher(key, context, L, c);
    cipher.print_parameters();
    std::cout << "HE encrypting key..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    cipher.encrypt_key();
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "initial noise:" << std::endl;
    cipher.print_noise();

    std::cout << "HE decrypting..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    std::vector<helib::Ctxt> he_ciph = cipher.HE_decrypt(ciph, BITSIZE * N);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "noise:" << std::endl;
    cipher.print_noise(he_ciph);

    typename T::e_vector vi_e(N);
    cipher.decode(vi_e, he_ciph, BITSIZE);

    typename T::e_vector vo_e;
    std::cout << "Computing in HE..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    cipher.affine(vo_e, mat, vi_e, b);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

    std::cout << "Final noise:" << std::endl;
    cipher.print_noise(vo_e[0]);

    std::cout << "Final decrypt..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < N; i++) {
      cipher.decrypt(vo_e[i], vo_p[i]);
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "... done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

    if (vo != vo_p) {
      std::cerr << cipher.get_cipher_name() << " KATS failed!\n";
      utils::print_vector("plain:  ", vo, std::cerr);
      utils::print_vector("cipher: ", vo_p, std::cerr);
      return false;
    }
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
      default: {
        std::cout << "Testcase not found... " << std::endl;
        return false;
      }
    }
  }
};
