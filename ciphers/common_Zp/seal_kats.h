#pragma once

#include "../common/utils.h"
#include "matrix.h"
#include "seal/seal.h"

template <class T>
class SEALKnownAnswerTestZp {
 public:
  enum Testcase { MAT, DEC, USE_CASE, PACKED_MAT, PACKED_USE_CASE };

 private:
  static constexpr bool PRESET_SEED = true;
  static constexpr size_t NUM_MATMULS_SQUARES = 3;
  static constexpr bool LAST_SQUARE = false;
  static constexpr bool MOD_SWITCH = false;
  static constexpr size_t MOD_SWITCH_LEVELS = 0;
  utils::SeededRandom rand;
  std::vector<uint64_t> key;
  std::vector<uint64_t> plaintext;
  std::vector<uint64_t> ciphertext_expected;
  uint64_t plain_mod;
  uint64_t mod_degree;
  int seclevel;
  Testcase tc;
  size_t N;
  bool use_bsgs;
  uint64_t bsgs_n1;
  uint64_t bsgs_n2;

  static const bool USE_BATCH = true;

 public:
  SEALKnownAnswerTestZp(std::vector<uint64_t> key,
                        std::vector<uint64_t> plaintext,
                        std::vector<uint64_t> ciphertext_expected,
                        uint64_t plain_mod, uint64_t mod_degree, int seclevel,
                        Testcase tc = DEC, size_t N = 4, bool use_bsgs = false,
                        uint64_t bsgs_n1 = 0, uint64_t bsgs_n2 = 0)
      : rand(PRESET_SEED),
        key(key),
        plaintext(plaintext),
        ciphertext_expected(ciphertext_expected),
        plain_mod(plain_mod),
        mod_degree(mod_degree),
        seclevel(seclevel),
        tc(tc),
        N(N),
        use_bsgs(use_bsgs),
        bsgs_n1(bsgs_n1),
        bsgs_n2(bsgs_n2) {}

  SEALKnownAnswerTestZp(const uint64_t* key, size_t key_size,
                        const uint64_t* plaintext, size_t plaintext_size,
                        const uint64_t* ciphertext_expected,
                        size_t ciphertext_size, uint64_t plain_mod,
                        uint64_t mod_degree, int seclevel, Testcase tc = DEC,
                        size_t N = 4, bool use_bsgs = false,
                        uint64_t bsgs_n1 = 0, uint64_t bsgs_n2 = 0)
      : rand(PRESET_SEED),
        key(key, key + key_size),
        plaintext(plaintext, plaintext + plaintext_size),
        ciphertext_expected(ciphertext_expected,
                            ciphertext_expected + ciphertext_size),
        plain_mod(plain_mod),
        mod_degree(mod_degree),
        seclevel(seclevel),
        tc(tc),
        N(N),
        use_bsgs(use_bsgs),
        bsgs_n1(bsgs_n1),
        bsgs_n2(bsgs_n2) {}

  bool mat_test() {
    std::cout << "Num matrices = " << NUM_MATMULS_SQUARES << std::endl;
    auto context = T::create_context(mod_degree, plain_mod, seclevel);
    T cipher(key, context);
    cipher.print_parameters();
    std::cout << "N = " << N << std::endl;
    std::cout << "Getting random elements..." << std::flush;

    // random matrices
    std::vector<matrix::matrix> m(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      m[r].resize(N);
      for (size_t i = 0; i < N; i++) {
        m[r][i].reserve(N);
        for (size_t j = 0; j < N; j++) {
          m[r][i].push_back(rand.random_uint64() %
                            plain_mod);  // not cryptosecure ;)
        }
      }
    }

    // random biases
    std::vector<matrix::vector> b(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      b[r].reserve(N);
      for (size_t i = 0; i < N; i++) {
        b[r].push_back(rand.random_uint64() %
                       plain_mod);  // not cryptosecure ;)
      }
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() % plain_mod);  // not cryptosecure ;)
    }

    std::cout << "...done" << std::endl;
    std::cout << "Computing in plain..." << std::flush;

    matrix::vector vo, vo_p(N), vi_tmp;
    vi_tmp = vi;
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      matrix::affine(vo, m[r], vi_tmp, b[r], plain_mod);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        matrix::square(vi_tmp, vo, plain_mod);
    }

    std::cout << "...done" << std::endl;
    std::cout << "Computing in HE..." << std::endl;

    // HE:
    std::vector<seal::Ciphertext> vi_e(N);
    std::vector<seal::Ciphertext> vo_e;
    for (size_t i = 0; i < N; i++) {
      cipher.encrypt(vi_e[i], vi[i], USE_BATCH);
    }
    std::cout << "initial noise:" << std::endl;
    cipher.print_noise(vi_e[0]);

    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      cipher.affine(vo_e, m[r], vi_e, b[r], USE_BATCH);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        cipher.square(vi_e, vo_e);
    }

    std::cout << "final noise:" << std::endl;
    cipher.print_noise(vo_e[0]);

    for (size_t i = 0; i < N; i++) {
      cipher.decrypt(vo_e[i], vo_p[i], USE_BATCH);
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

    auto context = T::create_context(mod_degree, plain_mod, seclevel);
    T cipher(key, context);
    cipher.print_parameters();
    cipher.activate_bsgs(use_bsgs);
    cipher.add_gk_indices();
    cipher.create_gk();

    std::cout << "HE encrypting key..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    cipher.encrypt_key(USE_BATCH);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

    std::cout << "initial noise:" << std::endl;
    cipher.print_noise();

    std::cout << "HE decrypting..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    std::vector<seal::Ciphertext> ciph =
        cipher.HE_decrypt(ciphertext_expected, USE_BATCH);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

    std::cout << "final noise:" << std::endl;
    cipher.print_noise(ciph);

    std::cout << "Final decrypt..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    std::vector<uint64_t> plain = cipher.decrypt_result(ciph, USE_BATCH);
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

    std::cout << "Num matrices = " << NUM_MATMULS_SQUARES << std::endl;
    std::cout << "N = " << N << std::endl;
    std::cout << "Getting random elements..." << std::flush;

    // random matrices
    std::vector<matrix::matrix> m(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      m[r].resize(N);
      for (size_t i = 0; i < N; i++) {
        m[r][i].reserve(N);
        for (size_t j = 0; j < N; j++) {
          m[r][i].push_back(rand.random_uint64() %
                            plain_mod);  // not cryptosecure ;)
        }
      }
    }

    // random biases
    std::vector<matrix::vector> b(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      b[r].reserve(N);
      for (size_t i = 0; i < N; i++) {
        b[r].push_back(rand.random_uint64() %
                       plain_mod);  // not cryptosecure ;)
      }
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() % plain_mod);  // not cryptosecure ;)
    }

    std::cout << "...done" << std::endl;

    std::cout << "Computing in plain..." << std::flush;

    matrix::vector vo, vo_p(N), vi_tmp;
    vi_tmp = vi;
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      matrix::affine(vo, m[r], vi_tmp, b[r], plain_mod);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        matrix::square(vi_tmp, vo, plain_mod);
    }

    std::cout << "...done" << std::endl;

    std::cout << "Encrypting input..." << std::flush;
    typename T::Plain plain_cipher(key, plain_mod);
    time_start = std::chrono::high_resolution_clock::now();
    std::vector<uint64_t> ciph = plain_cipher.encrypt(vi);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

    auto context = T::create_context(mod_degree, plain_mod, seclevel);
    T cipher(key, context);
    cipher.print_parameters();
    std::cout << "HE encrypting key..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    cipher.encrypt_key(USE_BATCH);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "initial noise:" << std::endl;
    cipher.print_noise();

    std::cout << "HE decrypting..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    std::vector<seal::Ciphertext> vi_e = cipher.HE_decrypt(ciph, USE_BATCH);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "noise:" << std::endl;
    cipher.print_noise(vi_e);

    std::vector<seal::Ciphertext> vo_e;
    std::cout << "Computing in HE..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      cipher.affine(vo_e, m[r], vi_e, b[r], USE_BATCH);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        cipher.square(vi_e, vo_e);
    }
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
      cipher.decrypt(vo_e[i], vo_p[i], USE_BATCH);
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

  bool packed_mat_test() {
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::milliseconds time_diff;

    auto context = T::create_context(mod_degree, plain_mod, seclevel);
    T cipher(key, context);
    cipher.print_parameters();
    std::cout << "Num matrices = " << NUM_MATMULS_SQUARES << std::endl;
    std::cout << "N = " << N << std::endl;
    std::cout << "Getting random elements..." << std::flush;
    cipher.activate_bsgs(use_bsgs);
    if (use_bsgs)
      cipher.add_bsgs_indices(bsgs_n1, bsgs_n2);
    else
      cipher.add_diagonal_indices(N);
    cipher.create_gk();

    // random matrices
    std::vector<matrix::matrix> m(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      m[r].resize(N);
      for (size_t i = 0; i < N; i++) {
        m[r][i].reserve(N);
        for (size_t j = 0; j < N; j++) {
          m[r][i].push_back(rand.random_uint64() %
                            plain_mod);  // not cryptosecure ;)
        }
      }
    }

    // random biases
    std::vector<matrix::vector> b(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      b[r].reserve(N);
      for (size_t i = 0; i < N; i++) {
        b[r].push_back(rand.random_uint64() %
                       plain_mod);  // not cryptosecure ;)
      }
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() % plain_mod);  // not cryptosecure ;)
    }

    std::cout << "...done" << std::endl;
    std::cout << "Computing in plain..." << std::flush;

    matrix::vector vo, vo_p(N), vi_tmp;
    vi_tmp = vi;
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      matrix::affine(vo, m[r], vi_tmp, b[r], plain_mod);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        matrix::square(vi_tmp, vo, plain_mod);
    }

    std::cout << "...done" << std::endl;
    std::cout << "Computing in HE..." << std::endl;

    // HE:
    seal::Ciphertext vi_e;
    seal::Ciphertext vo_e;
    time_start = std::chrono::high_resolution_clock::now();
    cipher.packed_encrypt(vi_e, vi);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "Encryption time: " << time_diff.count() << " milliseconds"
              << std::endl;
    auto size = cipher.get_cipher_size(vi_e);
    std::cout << "Ciphertext size = " << size << " Bytes" << std::endl;

    std::cout << "initial noise:" << std::endl;
    cipher.print_noise(vi_e);

    if (use_bsgs) cipher.set_bsgs_params(bsgs_n1, bsgs_n2);
    time_start = std::chrono::high_resolution_clock::now();
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      cipher.packed_affine(vo_e, m[r], vi_e, b[r]);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        cipher.packed_square(vi_e, vo_e);
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "Computation time: " << time_diff.count() << " milliseconds"
              << std::endl;

    std::cout << "final noise:" << std::endl;
    cipher.print_noise(vo_e);

    size = cipher.get_cipher_size(vo_e, MOD_SWITCH, MOD_SWITCH_LEVELS);
    std::cout << "Final ciphertext size = " << size << " Bytes" << std::endl;

    time_start = std::chrono::high_resolution_clock::now();
    cipher.packed_decrypt(vo_e, vo_p, N);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "Decryption time: " << time_diff.count() << " milliseconds"
              << std::endl;

    std::cout << "...done" << std::endl;
    if (vo != vo_p) {
      std::cerr << cipher.get_cipher_name() << " KATS failed!\n";
      utils::print_vector("plain:  ", vo, std::cerr);
      utils::print_vector("cipher: ", vo_p, std::cerr);
      return false;
    }
    return true;
  }

  bool packed_test() {
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::milliseconds time_diff;

    std::cout << "Num matrices = " << NUM_MATMULS_SQUARES << std::endl;
    std::cout << "N = " << N << std::endl;
    std::cout << "Getting random elements..." << std::flush;

    // random matrices
    std::vector<matrix::matrix> m(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      m[r].resize(N);
      for (size_t i = 0; i < N; i++) {
        m[r][i].reserve(N);
        for (size_t j = 0; j < N; j++) {
          m[r][i].push_back(rand.random_uint64() %
                            plain_mod);  // not cryptosecure ;)
        }
      }
    }

    // random biases
    std::vector<matrix::vector> b(NUM_MATMULS_SQUARES);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      b[r].reserve(N);
      for (size_t i = 0; i < N; i++) {
        b[r].push_back(rand.random_uint64() %
                       plain_mod);  // not cryptosecure ;)
      }
    }

    // random input vector
    matrix::vector vi;
    vi.reserve(N);
    for (size_t i = 0; i < N; i++) {
      vi.push_back(rand.random_uint64() % plain_mod);  // not cryptosecure ;)
    }

    std::cout << "...done" << std::endl;

    std::cout << "Computing in plain..." << std::flush;

    matrix::vector vo, vo_p(N), vi_tmp;
    vi_tmp = vi;
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      matrix::affine(vo, m[r], vi_tmp, b[r], plain_mod);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        matrix::square(vi_tmp, vo, plain_mod);
    }

    std::cout << "...done" << std::endl;

    std::cout << "Encrypting input..." << std::flush;
    typename T::Plain plain_cipher(key, plain_mod);
    time_start = std::chrono::high_resolution_clock::now();
    std::vector<uint64_t> ciph = plain_cipher.encrypt(vi);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

    auto context = T::create_context(mod_degree, plain_mod, seclevel);
    T cipher(key, context);
    cipher.print_parameters();
    size_t rem = N % cipher.get_plain_size();
    size_t num_block = N / cipher.get_plain_size();
    if (rem) num_block++;
    std::vector<int> flatten_gks;
    for (int i = 1; i < num_block; i++)
      flatten_gks.push_back(-(int)(i * cipher.get_plain_size()));

    cipher.activate_bsgs(use_bsgs);
    cipher.add_gk_indices();
    cipher.add_some_gk_indices(flatten_gks);
    if (use_bsgs)
      cipher.add_bsgs_indices(bsgs_n1, bsgs_n2);
    else
      cipher.add_diagonal_indices(N);
    cipher.create_gk();

    std::cout << "HE encrypting key..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    cipher.encrypt_key(USE_BATCH);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "initial noise:" << std::endl;
    cipher.print_noise();

    std::cout << "HE decrypting..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    seal::Ciphertext vi_e;
    std::vector<seal::Ciphertext> vi_e_vec = cipher.HE_decrypt(ciph, USE_BATCH);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "noise:" << std::endl;
    cipher.print_noise(vi_e_vec);

    std::cout << "HE postprocessing..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    if (rem != 0) {
      std::vector<uint64_t> mask(rem, 1);
      cipher.mask(vi_e_vec.back(), mask);
    }
    cipher.flatten(vi_e_vec, vi_e);
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;
    std::cout << "noise:" << std::endl;
    cipher.print_noise(vi_e);

    seal::Ciphertext vo_e;
    std::cout << "Computing in HE..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    if (use_bsgs) cipher.set_bsgs_params(bsgs_n1, bsgs_n2);
    for (size_t r = 0; r < NUM_MATMULS_SQUARES; r++) {
      cipher.packed_affine(vo_e, m[r], vi_e, b[r]);
      if (!LAST_SQUARE && r != NUM_MATMULS_SQUARES - 1)
        cipher.packed_square(vi_e, vo_e);
    }
    time_end = std::chrono::high_resolution_clock::now();
    time_diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        time_end - time_start);
    std::cout << "...done" << std::endl;
    std::cout << "Time: " << time_diff.count() << " milliseconds" << std::endl;

    std::cout << "Final noise:" << std::endl;
    cipher.print_noise(vo_e);

    auto size = cipher.get_cipher_size(vo_e, MOD_SWITCH, MOD_SWITCH_LEVELS);
    std::cout << "Final ciphertext size = " << size << " Bytes" << std::endl;

    std::cout << "Final decrypt..." << std::flush;
    time_start = std::chrono::high_resolution_clock::now();
    cipher.packed_decrypt(vo_e, vo_p, N);
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
      case PACKED_MAT:
        return packed_mat_test();
      case PACKED_USE_CASE:
        return packed_test();
      default: {
        std::cout << "Testcase not found... " << std::endl;
        return false;
      }
    }
  }
};
