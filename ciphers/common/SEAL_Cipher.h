#pragma once

// an abstract interface of a cipher, for evaluation in SEAL

#include "Cipher.h"
#include "seal/seal.h"

class SEALCipher {
 public:
  typedef seal::Ciphertext e_bit;
  typedef std::vector<e_bit> e_int;
  typedef std::vector<e_int> e_vector;
  typedef std::vector<e_vector> e_matrix;
  typedef std::vector<uint64_t> vector;
  typedef std::vector<std::vector<uint64_t>> matrix;

 protected:
  std::vector<uint8_t> secret_key;
  BlockCipherParams params;
  uint64_t plain_mod;
  uint64_t mod_degree;

  std::vector<seal::Ciphertext> secret_key_encrypted;

  std::shared_ptr<seal::SEALContext> context;
  seal::KeyGenerator keygen;

  seal::SecretKey he_sk;
  seal::PublicKey he_pk;
  seal::RelinKeys he_rk;

  seal::Encryptor encryptor;
  seal::Evaluator evaluator;
  seal::Decryptor decryptor;

  void CLAinternal(e_int& s, size_t bitsize, size_t levels, size_t size,
                   std::vector<std::vector<e_bit>>& g,
                   std::vector<std::vector<e_bit>>& p, std::vector<e_bit>& c);
  void fpg(const std::vector<e_bit>& g, const std::vector<e_bit>& p, size_t i,
           e_bit& out_g, e_bit& out_p);

  void treeAdd(std::vector<e_int>& tree);
  // helper for mul
  void treeAddMul(std::vector<e_int>& tree);

 public:
  SEALCipher(BlockCipherParams params, std::vector<uint8_t> secret_key,
             std::shared_ptr<seal::SEALContext> con);

  virtual ~SEALCipher() = default;
  // Size of the secret key in bytes
  size_t get_key_size_bytes() const { return params.key_size_bytes; }
  // Size of the secret key in bits
  size_t get_key_size_bits() const { return params.key_size_bits; }
  // Size of a plaintext block in bytes
  size_t get_plain_size_bytes() const { return params.plain_size_bytes; }
  // Size of a plaintext block in bits
  size_t get_plain_size_bits() const { return params.plain_size_bits; }
  // Size of a plaintext block in bytes
  size_t get_cipher_size_bytes() const { return params.cipher_size_bytes; }
  // Size of a plaintext block in bits
  size_t get_cipher_size_bits() const { return params.cipher_size_bits; }

  // A displayable name for this cipher
  virtual std::string get_cipher_name() const = 0;

  static std::shared_ptr<seal::SEALContext> create_context(size_t mod_degree,
                                                           uint64_t plain_mod,
                                                           int seclevel = 128);
  virtual void encrypt_key() = 0;
  virtual std::vector<seal::Ciphertext> HE_decrypt(
      std::vector<uint8_t>& ciphertext, size_t bits) = 0;
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<seal::Ciphertext>& ciphertexts) = 0;

  void print_parameters();
  int print_noise();
  int print_noise(std::vector<seal::Ciphertext>& ciphs);
  int print_noise(seal::Ciphertext& ciph);

  void halfAdder(e_bit& c_out, e_bit& s, const e_bit& a, const e_bit& b);
  void fullAdder(e_bit& c_out, e_bit& s, const e_bit& a, const e_bit& b,
                 const e_bit& c_in);

  // n-bit
  void rippleCarryAdder(e_int& s, const e_int& a, const e_int& b);
  void carryLookaheadAdder(e_int& s, const e_int& a, const e_int& b,
                           int levels = 2, int size = 4);

  // n x n = n bit multiplier
  void multiply(e_int& s, const e_int& a, const e_int& b);

  // n x n = n bit multiplier
  void multiplyPlain(e_int& s, const e_int& a, const uint64_t b);

  void halfAdderPlain(e_bit& c_out, e_bit& s, const e_bit& a, const bool b);
  void fullAdderPlain(e_bit& c_out, e_bit& s, const e_bit& a, const bool b,
                      const e_bit& c_in);
  void rippleCarryAdderPlain(e_int& s, const e_int& a, const uint64_t b);
  void carryLookaheadAdderPlain(e_int& s, const e_int& a, const uint64_t b,
                                int levels = 2, int size = 4);

  void encrypt(e_int& out, uint16_t in);
  void encrypt(e_int& out, uint64_t in, size_t bitsize = 64);
  void decrypt(e_int& in, uint16_t& out);
  void decrypt(e_int& in, uint64_t& out);

  void decode(e_vector& out, std::vector<seal::Ciphertext> encoded,
              size_t bitsize);

  // vo = M * vi
  void matMul(e_vector& vo, const matrix& M, const e_vector& vi);

  // vo = vi + b
  void vecAdd(e_vector& vo, const e_vector& vi, const vector& b);

  // vo = M * vi + b
  void affine(e_vector& vo, const matrix& M, const e_vector& vi,
              const vector& b);
};
