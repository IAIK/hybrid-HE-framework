#include "SEAL_Cipher.h"

#include <algorithm>
#include <iostream>

SEALZpCipher::SEALZpCipher(ZpCipherParams params,
                           std::vector<uint64_t> secret_key,
                           std::shared_ptr<seal::SEALContext> con)
    : secret_key(secret_key),
      params(params),
      context(con),
      keygen(*context),
      he_sk(keygen.secret_key()),
      encryptor(*context, he_sk),
      evaluator(*context),
      decryptor(*context, he_sk),
      batch_encoder(*context) {
  if (secret_key.size() != params.key_size)
    throw std::runtime_error("Invalid Key length");

  keygen.create_relin_keys(he_rk);
  keygen.create_public_key(he_pk);
  encryptor.set_public_key(he_pk);

  mod_degree = context->first_context_data()->parms().poly_modulus_degree();
  plain_mod = context->first_context_data()->parms().plain_modulus().value();
}

std::shared_ptr<seal::SEALContext> SEALZpCipher::create_context(
    size_t mod_degree, uint64_t plain_mod, int seclevel) {
  if (seclevel != 128) throw std::runtime_error("Security Level not supported");
  seal::sec_level_type sec = seal::sec_level_type::tc128;

  seal::EncryptionParameters parms(seal::scheme_type::bfv);
  parms.set_poly_modulus_degree(mod_degree);
  if (mod_degree == 65536) {
    sec = seal::sec_level_type::none;
    parms.set_coeff_modulus(
        {0xffffffffffc0001, 0xfffffffff840001, 0xfffffffff6a0001,
         0xfffffffff5a0001, 0xfffffffff2a0001, 0xfffffffff240001,
         0xffffffffefe0001, 0xffffffffeca0001, 0xffffffffe9e0001,
         0xffffffffe7c0001, 0xffffffffe740001, 0xffffffffe520001,
         0xffffffffe4c0001, 0xffffffffe440001, 0xffffffffe400001,
         0xffffffffdda0001, 0xffffffffdd20001, 0xffffffffdbc0001,
         0xffffffffdb60001, 0xffffffffd8a0001, 0xffffffffd840001,
         0xffffffffd6e0001, 0xffffffffd680001, 0xffffffffd2a0001,
         0xffffffffd000001, 0xffffffffcf00001, 0xffffffffcea0001,
         0xffffffffcdc0001, 0xffffffffcc40001});  // 1740 bits
  } else {
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(mod_degree));
  }
  parms.set_plain_modulus(plain_mod);
  return std::make_shared<seal::SEALContext>(parms, true, sec);
}

//----------------------------------------------------------------
int SEALZpCipher::print_noise() { return print_noise(secret_key_encrypted); }

//----------------------------------------------------------------

int SEALZpCipher::print_noise(std::vector<seal::Ciphertext>& ciphs) {
  int min = decryptor.invariant_noise_budget(ciphs[0]);
  int max = min;
  for (uint64_t i = 1; i < ciphs.size(); i++) {
    int budget = decryptor.invariant_noise_budget(ciphs[i]);
    if (budget > max) max = budget;
    if (budget < min) min = budget;
  }
  std::cout << "min noise budget: " << min << std::endl;
  std::cout << "max noise budget: " << max << std::endl;
  return min;
}

//----------------------------------------------------------------

int SEALZpCipher::print_noise(seal::Ciphertext& ciph) {
  int noise = decryptor.invariant_noise_budget(ciph);
  std::cout << "noise budget: " << noise << std::endl;
  return noise;
}

//----------------------------------------------------------------

void SEALZpCipher::print_parameters() {
  // Verify parameters
  if (!context) {
    throw std::invalid_argument("context is not set");
  }
  auto& context_data = *context->key_context_data();

  /*
  Which scheme are we using?
  */
  std::string scheme_name;
  switch (context_data.parms().scheme()) {
    case seal::scheme_type::bfv:
      scheme_name = "BFV";
      break;
    case seal::scheme_type::ckks:
      scheme_name = "CKKS";
      break;
    default:
      throw std::invalid_argument("unsupported scheme");
  }
  std::cout << "/" << std::endl;
  std::cout << "| Encryption parameters:" << std::endl;
  std::cout << "|   scheme: " << scheme_name << std::endl;
  std::cout << "|   poly_modulus_degree: "
            << context_data.parms().poly_modulus_degree() << std::endl;

  /*
  Print the size of the true (product) coefficient modulus.
  */
  std::cout << "|   coeff_modulus size: ";
  std::cout << context_data.total_coeff_modulus_bit_count() << " (";
  auto coeff_modulus = context_data.parms().coeff_modulus();
  std::size_t coeff_mod_count = coeff_modulus.size();
  for (std::size_t i = 0; i < coeff_mod_count - 1; i++) {
    std::cout << coeff_modulus[i].bit_count() << " + ";
  }
  std::cout << coeff_modulus.back().bit_count();
  std::cout << ") bits" << std::endl;

  /*
  For the BFV scheme print the plain_modulus parameter.
  */
  if (context_data.parms().scheme() == seal::scheme_type::bfv) {
    std::cout << "|   plain_modulus: "
              << context_data.parms().plain_modulus().value() << std::endl;
  }

  std::cout << "\\" << std::endl;
}

//----------------------------------------------------------------

void SEALZpCipher::mask(seal::Ciphertext& cipher, std::vector<uint64_t>& mask) {
  seal::Plaintext p;
  batch_encoder.encode(mask, p);
  evaluator.multiply_plain_inplace(cipher, p);
}

//----------------------------------------------------------------

void SEALZpCipher::flatten(std::vector<seal::Ciphertext>& in,
                           seal::Ciphertext& out) {
  out = in[0];
  seal::Ciphertext tmp;
  for (size_t i = 1; i < in.size(); i++) {
    evaluator.rotate_rows(in[i], -(int)(i * params.plain_size), he_gk, tmp);
    evaluator.add_inplace(out, tmp);
  }
}

//----------------------------------------------------------------

void SEALZpCipher::babystep_giantstep(seal::Ciphertext& in_out,
                                      const matrix& mat) {
  const size_t matrix_dim = mat.size();

  size_t nslots = batch_encoder.slot_count();

  if (matrix_dim * 2 != nslots && matrix_dim * 4 > nslots)
    throw std::runtime_error("too little slots for matmul implementation!");

  if (bsgs_n1 * bsgs_n2 != matrix_dim)
    std::cout << "WARNING: wrong bsgs parameters" << std::endl;

  // diagonal method preperation:
  std::vector<seal::Plaintext> matrix;
  matrix.reserve(matrix_dim);
  for (auto i = 0ULL; i < matrix_dim; i++) {
    std::vector<uint64_t> diag;
    auto k = i / bsgs_n1;
    diag.reserve(matrix_dim + k * bsgs_n1);

    for (auto j = 0ULL; j < matrix_dim; j++) {
      diag.push_back(mat[j][(i + j) % matrix_dim]);
    }
    // rotate:
    if (k)
      std::rotate(diag.begin(), diag.begin() + diag.size() - k * bsgs_n1,
                  diag.end());

    // prepare for non-full-packed rotations
    if (nslots != matrix_dim * 2) {
      for (uint64_t index = 0; index < k * bsgs_n1; index++) {
        diag.push_back(diag[index]);
        diag[index] = 0;
      }
    }

    seal::Plaintext row;
    batch_encoder.encode(diag, row);
    matrix.push_back(row);
  }

  // prepare for non-full-packed rotations
  if (nslots != matrix_dim * 2) {
    seal::Ciphertext state_rot;
    evaluator.rotate_rows(in_out, -((int)matrix_dim), he_gk, state_rot);
    evaluator.add_inplace(in_out, state_rot);
  }

  seal::Ciphertext temp;
  seal::Ciphertext outer_sum;
  seal::Ciphertext inner_sum;

  // prepare rotations
  std::vector<seal::Ciphertext> rot;
  rot.resize(bsgs_n1);
  rot[0] = in_out;
  for (uint64_t j = 1; j < bsgs_n1; j++)
    evaluator.rotate_rows(rot[j - 1], 1, he_gk, rot[j]);

  for (uint64_t k = 0; k < bsgs_n2; k++) {
    evaluator.multiply_plain(rot[0], matrix[k * bsgs_n1], inner_sum);
    for (uint64_t j = 1; j < bsgs_n1; j++) {
      evaluator.multiply_plain(rot[j], matrix[k * bsgs_n1 + j], temp);
      evaluator.add_inplace(inner_sum, temp);
    }
    if (!k)
      outer_sum = inner_sum;
    else {
      evaluator.rotate_rows_inplace(inner_sum, k * bsgs_n1, he_gk);
      evaluator.add_inplace(outer_sum, inner_sum);
    }
  }
  in_out = outer_sum;
}

//----------------------------------------------------------------

void SEALZpCipher::diagonal(seal::Ciphertext& in_out, const matrix& mat) {
  const size_t matrix_dim = mat.size();
  size_t nslots = batch_encoder.slot_count();

  if (matrix_dim * 2 != nslots && matrix_dim * 4 > nslots)
    throw std::runtime_error("too little slots for matmul implementation!");

  // non-full-packed rotation preparation
  if (nslots != matrix_dim * 2) {
    seal::Ciphertext in_rot;
    evaluator.rotate_rows(in_out, -((int)matrix_dim), he_gk, in_rot);
    evaluator.add_inplace(in_out, in_rot);
  }

  // diagonal method preperation:
  std::vector<seal::Plaintext> matrix;
  matrix.reserve(matrix_dim);
  for (auto i = 0ULL; i < matrix_dim; i++) {
    std::vector<uint64_t> diag;
    diag.reserve(matrix_dim);
    for (auto j = 0ULL; j < matrix_dim; j++) {
      diag.push_back(mat[j][(i + j) % matrix_dim]);
    }
    seal::Plaintext row;
    batch_encoder.encode(diag, row);
    matrix.push_back(row);
  }

  seal::Ciphertext sum = in_out;
  evaluator.multiply_plain_inplace(sum, matrix[0]);
  for (auto i = 1ULL; i < matrix_dim; i++) {
    seal::Ciphertext tmp;
    evaluator.rotate_rows_inplace(in_out, 1, he_gk);
    evaluator.multiply_plain(in_out, matrix[i], tmp);
    evaluator.add_inplace(sum, tmp);
  }
  in_out = sum;
}

//----------------------------------------------------------------

void SEALZpCipher::activate_bsgs(bool activate) { use_bsgs = activate; }

//----------------------------------------------------------------

void SEALZpCipher::set_bsgs_params(uint64_t n1, uint64_t n2) {
  bsgs_n1 = n1;
  bsgs_n2 = n2;
}

//----------------------------------------------------------------

void SEALZpCipher::add_some_gk_indices(std::vector<int>& gk_ind) {
  for (auto& it : gk_ind) gk_indices.push_back(it);
}

//----------------------------------------------------------------

void SEALZpCipher::add_bsgs_indices(uint64_t n1, uint64_t n2) {
  size_t mul = n1 * n2;
  add_diagonal_indices(mul);
  if (n1 == 1 || n2 == 1) return;

  for (uint64_t k = 1; k < n2; k++) gk_indices.push_back(k * n1);
}

//----------------------------------------------------------------

void SEALZpCipher::add_diagonal_indices(size_t size) {
  if (size * 2 != batch_encoder.slot_count())
    gk_indices.push_back(-((int)size));
  gk_indices.push_back(1);
}

//----------------------------------------------------------------

void SEALZpCipher::create_gk() { keygen.create_galois_keys(gk_indices, he_gk); }

//----------------------------------------------------------------

size_t SEALZpCipher::get_cipher_size(seal::Ciphertext& ct, bool mod_switch,
                                     size_t levels_from_last) {
  if (mod_switch) {
    auto c = context->last_context_data();
    for (uint64_t _ = 0; _ < levels_from_last; _++) {
      c = c->prev_context_data();
    }
    evaluator.mod_switch_to_inplace(ct, c->parms_id());
  }
  std::stringstream s;
  auto size = ct.save(s);
  return size;
}

//----------------------------------------------------------------
// non-packed:
//----------------------------------------------------------------

void SEALZpCipher::encrypt(seal::Ciphertext& out, uint64_t in,
                           bool batch_encoder) {
  seal::Plaintext p;
  if (batch_encoder)
    this->batch_encoder.encode(std::vector<uint64_t>(1, in), p);
  else
    p = in;

  encryptor.encrypt(p, out);
}

//----------------------------------------------------------------

void SEALZpCipher::decrypt(seal::Ciphertext& in, uint64_t& out,
                           bool batch_encoder) {
  seal::Plaintext p;
  decryptor.decrypt(in, p);

  if (batch_encoder) {
    std::vector<uint64_t> tmp;
    this->batch_encoder.decode(p, tmp);
    out = tmp[0];
  } else
    out = p[0];
}

//----------------------------------------------------------------

// vo = M * vi
void SEALZpCipher::matMul(std::vector<seal::Ciphertext>& vo, const matrix& M,
                          const std::vector<seal::Ciphertext>& vi,
                          bool batch_encoder) {
  size_t cols = vi.size();
  size_t rows = M.size();
  if (vo.size() != rows) vo.resize(rows);

  seal::Plaintext p;

  for (size_t row = 0; row < rows; row++) {
    for (size_t col = 0; col < cols; col++) {
      if (batch_encoder)
        this->batch_encoder.encode(std::vector<uint64_t>(1, M[row][col]), p);
      else
        p = M[row][col];
      seal::Ciphertext tmp;
      evaluator.multiply_plain(vi[col], p, tmp);
      if (col == 0)
        vo[row] = tmp;
      else
        evaluator.add_inplace(vo[row], tmp);
    }
  }
}

//----------------------------------------------------------------

// vo = vi + b
void SEALZpCipher::vecAdd(std::vector<seal::Ciphertext>& vo,
                          const std::vector<seal::Ciphertext>& vi,
                          const vector& b, bool batch_encoder) {
  size_t rows = vi.size();
  if (vo.size() != rows) vo.resize(rows);

  seal::Plaintext p;

  for (size_t row = 0; row < rows; row++) {
    if (batch_encoder)
      this->batch_encoder.encode(std::vector<uint64_t>(1, b[row]), p);
    else
      p = b[row];
    evaluator.add_plain(vi[row], p, vo[row]);
  }
}

//----------------------------------------------------------------

// vo = M * vi + b
void SEALZpCipher::affine(std::vector<seal::Ciphertext>& vo, const matrix& M,
                          const std::vector<seal::Ciphertext>& vi,
                          const vector& b, bool batch_encoder) {
  matMul(vo, M, vi, batch_encoder);
  vecAdd(vo, vo, b, batch_encoder);
}

//----------------------------------------------------------------

void SEALZpCipher::square(std::vector<seal::Ciphertext>& vo,
                          const std::vector<seal::Ciphertext>& vi) {
  size_t rows = vi.size();
  if (vo.size() != rows) vo.resize(rows);

  for (size_t row = 0; row < rows; row++) {
    evaluator.square(vi[row], vo[row]);
    evaluator.relinearize_inplace(vo[row], he_rk);
  }
}

//----------------------------------------------------------------
// packed:
//----------------------------------------------------------------

void SEALZpCipher::packed_encrypt(seal::Ciphertext& out,
                                  std::vector<uint64_t> in) {
  seal::Plaintext p;
  batch_encoder.encode(in, p);
  encryptor.encrypt(p, out);
}

//----------------------------------------------------------------

void SEALZpCipher::packed_decrypt(seal::Ciphertext& in,
                                  std::vector<uint64_t>& out, size_t size) {
  seal::Plaintext p;
  decryptor.decrypt(in, p);
  batch_encoder.decode(p, out);
  out.resize(size);
}

//----------------------------------------------------------------

// vo = M * vi
void SEALZpCipher::packed_matMul(seal::Ciphertext& vo, const matrix& M,
                                 const seal::Ciphertext& vi) {
  vo = vi;
  if (use_bsgs && bsgs_n1 != 1 && bsgs_n2 != 1)
    babystep_giantstep(vo, M);
  else
    diagonal(vo, M);
}

//----------------------------------------------------------------

// vo = M * vi + b
void SEALZpCipher::packed_affine(seal::Ciphertext& vo, const matrix& M,
                                 const seal::Ciphertext& vi, const vector& b) {
  packed_matMul(vo, M, vi);

  seal::Plaintext p;
  batch_encoder.encode(b, p);
  evaluator.add_plain_inplace(vo, p);
}

//----------------------------------------------------------------

void SEALZpCipher::packed_square(seal::Ciphertext& vo,
                                 const seal::Ciphertext& vi) {
  evaluator.square(vi, vo);
  evaluator.relinearize_inplace(vo, he_rk);
}
