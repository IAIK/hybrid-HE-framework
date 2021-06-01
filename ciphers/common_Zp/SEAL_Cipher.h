#pragma once

// an abstract interface of a Z_p cipher, for evaluation in SEAL

#include "Cipher.h"
#include "seal/seal.h"

class SEALZpCipher {
 public:
  typedef std::vector<uint64_t> vector;
  typedef std::vector<std::vector<uint64_t>> matrix;

 protected:
  std::vector<uint64_t> secret_key;
  ZpCipherParams params;
  uint64_t plain_mod;
  uint64_t mod_degree;

  std::vector<seal::Ciphertext> secret_key_encrypted;

  std::shared_ptr<seal::SEALContext> context;
  seal::KeyGenerator keygen;

  seal::SecretKey he_sk;
  seal::PublicKey he_pk;
  seal::RelinKeys he_rk;
  seal::GaloisKeys he_gk;

  seal::Encryptor encryptor;
  seal::Evaluator evaluator;
  seal::Decryptor decryptor;
  seal::BatchEncoder batch_encoder;

  std::vector<int> gk_indices;

  bool use_bsgs = false;
  size_t bsgs_n1;
  size_t bsgs_n2;

 public:
  SEALZpCipher(ZpCipherParams params, std::vector<uint64_t> secret_key,
               std::shared_ptr<seal::SEALContext> con);

  virtual ~SEALZpCipher() = default;
  // Size of the secret key in words
  size_t get_key_size() const { return params.key_size; }
  // Size of a plaintext block in words
  size_t get_plain_size() const { return params.plain_size; }
  // Size of a plaintext block in words
  size_t get_cipher_size() const { return params.cipher_size; }

  void add_some_gk_indices(std::vector<int>& gk_ind);
  void add_bsgs_indices(uint64_t bsgs_n1, uint64_t bsgs_n2);
  void add_diagonal_indices(size_t size);
  void create_gk();

  size_t get_cipher_size(seal::Ciphertext& ct, bool mod_switch = false,
                         size_t levels_from_last = 0);

  // A displayable name for this cipher
  virtual std::string get_cipher_name() const = 0;

  static std::shared_ptr<seal::SEALContext> create_context(size_t mod_degree,
                                                           uint64_t plain_mod,
                                                           int seclevel = 128);
  virtual void encrypt_key(bool batch_encoder = false) = 0;
  virtual std::vector<seal::Ciphertext> HE_decrypt(
      std::vector<uint64_t>& ciphertext, bool batch_encoder = false) = 0;
  virtual std::vector<uint64_t> decrypt_result(
      std::vector<seal::Ciphertext>& ciphertext,
      bool batch_encoder = false) = 0;
  virtual void add_gk_indices() = 0;

  void activate_bsgs(bool activate);
  void set_bsgs_params(uint64_t bsgs_n1, uint64_t bsgs_n2);

  void print_parameters();
  int print_noise();
  int print_noise(std::vector<seal::Ciphertext>& ciphs);
  int print_noise(seal::Ciphertext& ciph);

  void mask(seal::Ciphertext& cipher, std::vector<uint64_t>& mask);
  void flatten(std::vector<seal::Ciphertext>& in, seal::Ciphertext& out);

  void diagonal(seal::Ciphertext& in_out, const matrix& mat);
  void babystep_giantstep(seal::Ciphertext& in_out, const matrix& mat);

  // non-packed
  void encrypt(seal::Ciphertext& out, uint64_t in, bool batch_encoder = false);
  void decrypt(seal::Ciphertext& in, uint64_t& out, bool batch_encoder = false);
  // vo = M * vi
  void matMul(std::vector<seal::Ciphertext>& vo, const matrix& M,
              const std::vector<seal::Ciphertext>& vi,
              bool batch_encoder = false);
  // vo = vi + b
  void vecAdd(std::vector<seal::Ciphertext>& vo,
              const std::vector<seal::Ciphertext>& vi, const vector& b,
              bool batch_encoder = false);
  // vo = M * vi + b
  void affine(std::vector<seal::Ciphertext>& vo, const matrix& M,
              const std::vector<seal::Ciphertext>& vi, const vector& b,
              bool batch_encoder = false);
  void square(std::vector<seal::Ciphertext>& vo,
              const std::vector<seal::Ciphertext>& vi);

  // packed
  void packed_encrypt(seal::Ciphertext& out, std::vector<uint64_t> in);
  void packed_decrypt(seal::Ciphertext& in, std::vector<uint64_t>& out,
                      size_t size);
  // vo = M * vi
  void packed_matMul(seal::Ciphertext& vo, const matrix& M,
                     const seal::Ciphertext& vi);
  // vo = M * vi + b
  void packed_affine(seal::Ciphertext& vo, const matrix& M,
                     const seal::Ciphertext& vi, const vector& b);
  void packed_square(seal::Ciphertext& vo, const seal::Ciphertext& vi);
};
