#pragma once

// an abstract interface of a cipher, for evaluation in TFHE

#include <utility>

#include "Cipher.h"
#include "tfhe/tfhe.h"

class TFHECiphertextVec {
 private:
  LweSample* ct;
  int num;
  TFheGateBootstrappingParameterSet* params;

 public:
  TFHECiphertextVec();
  TFHECiphertextVec(int size, TFheGateBootstrappingParameterSet*);
  ~TFHECiphertextVec();

  void init(int size, TFheGateBootstrappingParameterSet*);
  TFHECiphertextVec(const TFHECiphertextVec&);
  TFHECiphertextVec& operator=(const TFHECiphertextVec&);
  TFHECiphertextVec(TFHECiphertextVec&& o)
      : ct(std::exchange(o.ct, nullptr)),
        num(std::exchange(o.num, 0)),
        params(std::exchange(o.params, nullptr)){};

  size_t size() const { return num; };

  LweSample& operator[](int);
  const LweSample& operator[](int) const;
};

class TFHECiphertext {
 private:
  LweSample* ct;
  TFheGateBootstrappingParameterSet* params;

 public:
  TFHECiphertext();
  TFHECiphertext(TFheGateBootstrappingParameterSet*);
  ~TFHECiphertext();

  void init(TFheGateBootstrappingParameterSet*);
  TFHECiphertext(const TFHECiphertext&);
  TFHECiphertext(TFHECiphertext&& o)
      : ct(std::exchange(o.ct, nullptr)),
        params(std::exchange(o.params, nullptr)){};

  TFHECiphertext& operator=(const TFHECiphertext&);
  TFHECiphertext& operator=(const LweSample&);

  operator LweSample&() { return *ct; }
  operator const LweSample&() const { return *ct; }
  operator LweSample*() { return ct; }
  operator const LweSample*() const { return ct; }
};

class TFHECipher {
 public:
  typedef LweSample e_bit;
  typedef TFHECiphertextVec e_int;
  typedef std::vector<e_int> e_vector;
  typedef std::vector<e_vector> e_matrix;
  typedef std::vector<uint64_t> vector;
  typedef std::vector<std::vector<uint64_t>> matrix;

 protected:
  std::vector<uint8_t> secret_key;
  BlockCipherParams params;

  TFHECiphertextVec secret_key_encrypted;

  TFheGateBootstrappingParameterSet* context;

  TFheGateBootstrappingSecretKeySet* he_sk;
  const TFheGateBootstrappingCloudKeySet* he_pk;

  void treeAdd(std::vector<e_int>& tree);
  // helper for mul
  void treeAddMul(std::vector<e_int>& tree);

 public:
  TFHECipher(BlockCipherParams params, std::vector<uint8_t> secret_key,
             int seclevel = 128);

  virtual ~TFHECipher();
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

  virtual void encrypt_key() = 0;
  virtual TFHECiphertextVec HE_decrypt(std::vector<uint8_t>& ciphertext,
                                       size_t bits) = 0;
  virtual std::vector<uint8_t> decrypt_result(
      TFHECiphertextVec& ciphertexts) = 0;

  void halfAdder(e_bit& c_out, e_bit& s, const e_bit& a, const e_bit& b);
  void fullAdder(e_bit& c_out, e_bit& s, const e_bit& a, const e_bit& b,
                 const e_bit& c_in);

  // n-bit
  void rippleCarryAdder(e_int& s, const e_int& a, const e_int& b);

  // n x n = n bit multiplier
  void multiply(e_int& s, const e_int& a, const e_int& b);

  // n x n = n bit multiplier
  void multiplyPlain(e_int& s, const e_int& a, const uint64_t b);

  void halfAdderPlain(e_bit& c_out, e_bit& s, const e_bit& a, const bool b);
  void fullAdderPlain(e_bit& c_out, e_bit& s, const e_bit& a, const bool b,
                      const e_bit& c_in);
  void rippleCarryAdderPlain(e_int& s, const e_int& a, const uint64_t b);

  void encrypt(e_int& out, uint16_t in);
  void encrypt(e_int& out, uint64_t in, size_t bitsize = 64);
  void decrypt(e_int& in, uint16_t& out);
  void decrypt(e_int& in, uint64_t& out);

  void decode(e_vector& out, TFHECiphertextVec encoded, size_t bitsize);

  // vo = M * vi
  void matMul(e_vector& vo, const matrix& M, const e_vector& vi);

  // vo = vi + b
  void vecAdd(e_vector& vo, const e_vector& vi, const vector& b);

  // vo = M * vi + b
  void affine(e_vector& vo, const matrix& M, const e_vector& vi,
              const vector& b);
};
