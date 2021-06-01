#pragma once

// an abstract interface of a Z_p cipher, for evaluation in HElib

#include "Cipher.h"
#include "helib/helib.h"

class HElibZpCipher {
 public:
  typedef std::vector<uint64_t> vector;
  typedef std::vector<std::vector<uint64_t>> matrix;
  static constexpr bool USE_HELIB_MATMUL_IMPL = true;

 protected:
  std::vector<uint64_t> secret_key;
  ZpCipherParams params;
  uint64_t plain_mod;

  std::shared_ptr<helib::Context> context;
  uint64_t nslots;

  std::vector<helib::Ctxt> secret_key_encrypted;

  helib::SecKey he_sk;
  std::unique_ptr<helib::PubKey> he_pk;
  const helib::EncryptedArray& ea;

  bool power_of_2_ring;
  std::set<long> gk_indices;

  bool use_bsgs = false;
  size_t bsgs_n1;
  size_t bsgs_n2;

  long get_elt_from_step(long step);

  bool isPowerOfTwo(long x);

 public:
  HElibZpCipher(ZpCipherParams params, std::vector<uint64_t> secret_key,
                std::shared_ptr<helib::Context> con, uint64_t L, uint64_t c,
                bool packed = false);

  virtual ~HElibZpCipher() = default;
  // Size of the secret key in words
  size_t get_key_size() const { return params.key_size; }
  // Size of a plaintext block in words
  size_t get_plain_size() const { return params.plain_size; }
  // Size of a plaintext block in words
  size_t get_cipher_size() const { return params.cipher_size; }

  void add_some_gk_indices(std::set<long>& gk_ind);
  void add_bsgs_indices(uint64_t bsgs_n1, uint64_t bsgs_n2);
  void add_diagonal_indices(size_t size);
  void create_pk(bool packed = false);

  size_t get_cipher_size(helib::Ctxt& ct, bool mod_switch = false);

  // A displayable name for this cipher
  virtual std::string get_cipher_name() const = 0;

  static std::shared_ptr<helib::Context> create_context(
      uint64_t m, uint64_t p, uint64_t r, uint64_t L, uint64_t c,
      uint64_t d = 1, uint64_t k = 128, uint64_t s = 1);
  virtual void encrypt_key() = 0;
  virtual std::vector<helib::Ctxt> HE_decrypt(
      std::vector<uint64_t>& ciphertext) = 0;
  virtual std::vector<uint64_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertexts) = 0;
  virtual void add_gk_indices() = 0;

  void activate_bsgs(bool activate);
  void set_bsgs_params(uint64_t bsgs_n1, uint64_t bsgs_n2);

  void print_parameters();
  int print_noise();
  int print_noise(std::vector<helib::Ctxt>& ciphs);
  int print_noise(helib::Ctxt& ciph);

  void mask(helib::Ctxt& cipher, std::vector<long>& mask);
  helib::Ctxt flatten(std::vector<helib::Ctxt>& in);

  void diagonal(helib::Ctxt& in_out, const matrix& mat);
  void babystep_giantstep(helib::Ctxt& in_out, const matrix& mat);
  void helib_matmul(helib::Ctxt& in_out, const matrix& mat);

  // non-packed
  void encrypt(helib::Ctxt& out, uint64_t in);
  void decrypt(helib::Ctxt& in, uint64_t& out);
  // vo = M * vi
  void matMul(std::vector<helib::Ctxt>& vo, const matrix& M,
              const std::vector<helib::Ctxt>& vi);
  // vo = vi + b
  void vecAdd(std::vector<helib::Ctxt>& vo, const std::vector<helib::Ctxt>& vi,
              const vector& b);
  // vo = M * vi + b
  void affine(std::vector<helib::Ctxt>& vo, const matrix& M,
              const std::vector<helib::Ctxt>& vi, const vector& b);
  void square(std::vector<helib::Ctxt>& vo, const std::vector<helib::Ctxt>& vi);

  // packed
  void encrypt(helib::Ctxt& ctxt, std::vector<long>& ptxt);
  void decrypt(helib::Ctxt& ctxt, std::vector<long>& ptxt);
  void encode(NTL::ZZX& enc, std::vector<long>& dec);
  void decode(NTL::ZZX& enc, std::vector<long>& dec);
  void rotate_rows(helib::Ctxt& ctxt, long step);
  void rotate_columns(helib::Ctxt& ctxt);
  void rotate(helib::Ctxt& ctxt, long step);

  helib::Ctxt packed_encrypt(std::vector<uint64_t> in);
  void packed_decrypt(helib::Ctxt& in, std::vector<uint64_t>& out, size_t size);
  // vo = M * vi
  helib::Ctxt packed_matMul(const matrix& M, const helib::Ctxt& vi);
  // vo = M * vi + b
  helib::Ctxt packed_affine(const matrix& M, const helib::Ctxt& vi,
                            const vector& b);
  helib::Ctxt packed_square(const helib::Ctxt& vi);
};
