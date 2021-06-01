#pragma once

// an abstract interface of a cipher, for evaluation in helib

#include "Cipher.h"
#include "helib/helib.h"

class HElibCipher {
 public:
  typedef helib::Ctxt e_bit;
  typedef std::vector<e_bit> e_int;
  typedef std::vector<e_int> e_vector;
  typedef std::vector<e_vector> e_matrix;
  typedef std::vector<uint64_t> vector;
  typedef std::vector<std::vector<uint64_t>> matrix;
  static constexpr bool USE_HELIB_CIRC_IMPL = false;
  static constexpr bool USE_HELIB_MATMUL_IMPL = true;

 protected:
  std::vector<uint8_t> secret_key;
  BlockCipherParams params;

  std::shared_ptr<helib::Context> context;
  long nslots;

  std::vector<helib::Ctxt> secret_key_encrypted;

  helib::SecKey he_sk;
  std::unique_ptr<helib::PubKey> he_pk;
  const helib::EncryptedArray& ea;

  void CLAinternal(e_int& s, size_t bitsize, size_t levels, size_t size,
                   std::vector<std::vector<e_bit>>& g,
                   std::vector<std::vector<e_bit>>& p, std::vector<e_bit>& c);
  void fpg(const std::vector<e_bit>& g, const std::vector<e_bit>& p, size_t i,
           e_bit& out_g, e_bit& out_p);

  void treeAdd(std::vector<e_int>& tree);
  // helper for mul
  void treeAddMul(std::vector<e_int>& tree);

  bool use_bsgs = false;
  size_t bsgs_n1;
  size_t bsgs_n2;

 public:
  HElibCipher(BlockCipherParams params, std::vector<uint8_t> secret_key,
              std::shared_ptr<helib::Context> con, long L, long c,
              bool packed = false);

  virtual ~HElibCipher() = default;
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

  static std::shared_ptr<helib::Context> create_context(long m, long p, long r,
                                                        long L, long c,
                                                        long d = 1,
                                                        long k = 128,
                                                        long s = 1);
  virtual void encrypt_key() = 0;
  virtual std::vector<helib::Ctxt> HE_decrypt(std::vector<uint8_t>& ciphertext,
                                              size_t bits) = 0;
  virtual std::vector<uint8_t> decrypt_result(
      std::vector<helib::Ctxt>& ciphertexts) = 0;

  void print_parameters();
  int print_noise();
  int print_noise(std::vector<helib::Ctxt>& ciphs);
  int print_noise(helib::Ctxt& ciph);

  void activate_bsgs(bool activate);
  void set_bsgs_params(uint64_t bsgs_n1, uint64_t bsgs_n2);

  void diagonal(helib::Ctxt& in_out,
                const std::vector<std::vector<uint8_t>>& mat);
  void babystep_giantstep(helib::Ctxt& in_out,
                          const std::vector<std::vector<uint8_t>>& mat);
  void helib_matmul(helib::Ctxt& in_out,
                    const std::vector<std::vector<uint8_t>>& mat);

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

  void decode(e_vector& out, std::vector<helib::Ctxt> encoded, size_t bitsize);

  // vo = M * vi
  void matMul(e_vector& vo, const matrix& M, const e_vector& vi);

  // vo = vi + b
  void vecAdd(e_vector& vo, const e_vector& vi, const vector& b);

  // vo = M * vi + b
  void affine(e_vector& vo, const matrix& M, const e_vector& vi,
              const vector& b);

  // vo = M * vi
  helib::Ctxt packed_matMul(const std::vector<std::vector<uint8_t>>& M,
                            const helib::Ctxt& vi);
  // vo = M * vi + b
  helib::Ctxt packed_affine(const std::vector<std::vector<uint8_t>>& M,
                            const helib::Ctxt& vi,
                            const std::vector<uint8_t>& b);
};
