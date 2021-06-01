#include "pasta_4_seal.h"

using namespace seal;

namespace PASTA_4 {

void PASTA_SEAL::encrypt_key(bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param
  secret_key_encrypted.resize(1);
  Plaintext k;
  std::vector<uint64_t> key_tmp(halfslots + PASTA_T, 0);
  for (size_t i = 0; i < PASTA_T; i++) {
    key_tmp[i] = secret_key[i];
    key_tmp[i + halfslots] = secret_key[i + PASTA_T];
  }
  this->batch_encoder.encode(key_tmp, k);
  encryptor.encrypt(k, secret_key_encrypted[0]);
}

//----------------------------------------------------------------

std::vector<Ciphertext> PASTA_SEAL::HE_decrypt(
    std::vector<uint64_t>& ciphertexts, bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param

  uint64_t nonce = 123456789;
  size_t size = ciphertexts.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  Pasta pasta(plain_mod);
  std::vector<Ciphertext> res(num_block);

  for (uint64_t b = 0; b < num_block; b++) {
    pasta.init_shake(nonce, b);
    Ciphertext state = secret_key_encrypted[0];

    for (uint8_t r = 1; r <= PASTA_R; r++) {
      std::cout << "round " << (int)r << std::endl;
      auto mat1 = pasta.get_random_matrix();
      auto mat2 = pasta.get_random_matrix();
      auto rc = pasta.get_rc_vec(halfslots);
      matmul(state, mat1, mat2);
      add_rc(state, rc);
      mix(state);
      if (r == PASTA_R)
        sbox_cube(state);
      else
        sbox_feistel(state);
      print_noise(state);
    }

    std::cout << "final add" << std::endl;
    auto mat1 = pasta.get_random_matrix();
    auto mat2 = pasta.get_random_matrix();
    auto rc = pasta.get_rc_vec(halfslots);
    matmul(state, mat1, mat2);
    add_rc(state, rc);
    mix(state);

    // remove second vector if needed
    if (REMOVE_SECOND_VEC) {
      std::vector<uint64_t> mask_vec(PASTA_T, 1);
      Plaintext mask;
      this->batch_encoder.encode(mask_vec, mask);
      evaluator.multiply_plain_inplace(state, mask);
    }

    // add cipher
    std::vector<uint64_t> cipher_tmp;
    cipher_tmp.insert(
        cipher_tmp.begin(), ciphertexts.begin() + b * params.cipher_size,
        ciphertexts.begin() + std::min((b + 1) * params.cipher_size, size));
    Plaintext p;
    this->batch_encoder.encode(cipher_tmp, p);
    evaluator.negate_inplace(state);
    evaluator.add_plain(state, p, res[b]);
  }
  return res;
}

//----------------------------------------------------------------

std::vector<uint64_t> PASTA_SEAL::decrypt_result(
    std::vector<Ciphertext>& ciphertext, bool batch_encoder) {
  (void)batch_encoder;  // patched implementation: ignore param
  Plaintext p;
  std::vector<uint64_t> res;
  decryptor.decrypt(ciphertext[0], p);
  this->batch_encoder.decode(p, res);
  res.resize(params.plain_size);
  return res;
}

//----------------------------------------------------------------

void PASTA_SEAL::add_gk_indices() {
  gk_indices.push_back(0);
  gk_indices.push_back(-1);
  if (PASTA_T * 2 != batch_encoder.slot_count())
    gk_indices.push_back(((int)PASTA_T));
  if (use_bsgs) {
    for (uint64_t k = 1; k < BSGS_N2; k++) gk_indices.push_back(-k * BSGS_N1);
  }
}

//----------------------------------------------------------------

void PASTA_SEAL::add_rc(seal::Ciphertext& state,
                        const std::vector<uint64_t>& rc) {
  Plaintext round_constants;
  batch_encoder.encode(rc, round_constants);
  evaluator.add_plain_inplace(state, round_constants);
}

//----------------------------------------------------------------

void PASTA_SEAL::sbox_cube(seal::Ciphertext& state) {
  evaluator.exponentiate_inplace(state, 3, he_rk);
}

//----------------------------------------------------------------

void PASTA_SEAL::sbox_feistel(seal::Ciphertext& state) {
  // rotate state
  Ciphertext state_rot;
  evaluator.rotate_rows(state, -1, he_gk, state_rot);

  // mask rotatet state
  Plaintext mask;
  std::vector<uint64_t> mask_vec(PASTA_T + halfslots, 1);
  mask_vec[0] = 0;
  mask_vec[halfslots] = 0;
  for (uint16_t i = PASTA_T; i < halfslots; i++) mask_vec[i] = 0;
  batch_encoder.encode(mask_vec, mask);
  evaluator.multiply_plain_inplace(state_rot, mask);
  // state_rot = 0, x_1, x_2, x_3, .... x_(t-1)

  // square
  evaluator.square_inplace(state_rot);
  evaluator.relinearize_inplace(state_rot, he_rk);
  // state_rot = 0, x_1^2, x_2^2, x_3^2, .... x_(t-1)^2

  // add
  evaluator.add_inplace(state, state_rot);
  // state = x_1, x_1^2 + x_2, x_2^2 + x_3, x_3^2 + x_4, .... x_(t-1)^2 + x_t
}

//----------------------------------------------------------------

void PASTA_SEAL::matmul(seal::Ciphertext& state,
                        const std::vector<std::vector<uint64_t>>& mat1,
                        const std::vector<std::vector<uint64_t>>& mat2) {
  if (use_bsgs) {
    babystep_giantstep(state, mat1, mat2);
  } else {
    diagonal(state, mat1, mat2);
  }
}

//----------------------------------------------------------------

void PASTA_SEAL::babystep_giantstep(
    seal::Ciphertext& state, const std::vector<std::vector<uint64_t>>& mat1,
    const std::vector<std::vector<uint64_t>>& mat2) {
  const size_t matrix_dim = PASTA_T;

  if (matrix_dim * 2 != slots && matrix_dim * 4 > slots)
    throw std::runtime_error("too little slots for matmul implementation!");

  if (BSGS_N1 * BSGS_N2 != matrix_dim)
    std::cout << "WARNING: wrong bsgs parameters" << std::endl;

  // diagonal method preperation:
  std::vector<Plaintext> matrix;
  matrix.reserve(matrix_dim);
  for (auto i = 0ULL; i < matrix_dim; i++) {
    std::vector<uint64_t> diag;
    diag.reserve(halfslots + matrix_dim);
    std::vector<uint64_t> tmp;
    tmp.reserve(matrix_dim);
    auto k = i / BSGS_N1;

    for (auto j = 0ULL; j < matrix_dim; j++) {
      diag.push_back(mat1[j][(j + matrix_dim - i) % matrix_dim]);
      tmp.push_back(mat2[j][(j + matrix_dim - i) % matrix_dim]);
    }

    // rotate:
    if (k) {
      std::rotate(diag.begin(), diag.begin() + k * BSGS_N1, diag.end());
      std::rotate(tmp.begin(), tmp.begin() + k * BSGS_N1, tmp.end());
    }

    // prepare for non-full-packed rotations
    if (halfslots != PASTA_T) {
      diag.resize(halfslots, 0);
      tmp.resize(halfslots, 0);
      for (uint64_t m = 0; m < k * BSGS_N1; m++) {
        uint64_t index_src = PASTA_T - 1 - m;
        uint64_t index_dest = halfslots - 1 - m;
        diag[index_dest] = diag[index_src];
        diag[index_src] = 0;
        tmp[index_dest] = tmp[index_src];
        tmp[index_src] = 0;
      }
    }
    // combine both diags
    diag.resize(slots, 0);
    for (size_t j = halfslots; j < slots; j++) {
      diag[j] = tmp[j - halfslots];
    }

    Plaintext row;
    batch_encoder.encode(diag, row);
    matrix.push_back(row);
  }

  // prepare for non-full-packed rotations
  if (halfslots != PASTA_T) {
    Ciphertext state_rot;
    evaluator.rotate_rows(state, ((int)PASTA_T), he_gk, state_rot);
    evaluator.add_inplace(state, state_rot);
  }

  Ciphertext temp;
  Ciphertext outer_sum;
  Ciphertext inner_sum;

  // prepare rotations
  std::vector<Ciphertext> rot;
  rot.resize(BSGS_N1);
  rot[0] = state;
  for (uint64_t j = 1; j < BSGS_N1; j++)
    evaluator.rotate_rows(rot[j - 1], -1, he_gk, rot[j]);

  for (uint64_t k = 0; k < BSGS_N2; k++) {
    evaluator.multiply_plain(rot[0], matrix[k * BSGS_N1], inner_sum);
    for (uint64_t j = 1; j < BSGS_N1; j++) {
      evaluator.multiply_plain(rot[j], matrix[k * BSGS_N1 + j], temp);
      evaluator.add_inplace(inner_sum, temp);
    }
    if (!k)
      outer_sum = inner_sum;
    else {
      evaluator.rotate_rows_inplace(inner_sum, -k * BSGS_N1, he_gk);
      evaluator.add_inplace(outer_sum, inner_sum);
    }
  }
  state = outer_sum;
}

//----------------------------------------------------------------

void PASTA_SEAL::diagonal(seal::Ciphertext& state,
                          const std::vector<std::vector<uint64_t>>& mat1,
                          const std::vector<std::vector<uint64_t>>& mat2) {
  const size_t matrix_dim = PASTA_T;

  if (matrix_dim * 2 != slots && matrix_dim * 4 > slots)
    throw std::runtime_error("too little slots for matmul implementation!");

  // non-full-packed rotation preparation
  if (halfslots != matrix_dim) {
    Ciphertext state_rot;
    evaluator.rotate_rows(state, ((int)matrix_dim), he_gk, state_rot);
    evaluator.add_inplace(state, state_rot);
  }

  // diagonal method preperation:
  std::vector<Plaintext> matrix;
  matrix.reserve(matrix_dim);
  for (auto i = 0ULL; i < matrix_dim; i++) {
    std::vector<uint64_t> diag(matrix_dim + halfslots, 0);
    for (auto j = 0ULL; j < matrix_dim; j++) {
      diag[j] = mat1[j][(j + matrix_dim - i) % matrix_dim];
      diag[j + halfslots] = mat2[j][(j + matrix_dim - i) % matrix_dim];
    }
    Plaintext row;
    batch_encoder.encode(diag, row);
    matrix.push_back(row);
  }

  Ciphertext sum = state;
  evaluator.multiply_plain_inplace(sum, matrix[0]);
  for (auto i = 1ULL; i < matrix_dim; i++) {
    Ciphertext tmp;
    evaluator.rotate_rows_inplace(state, -1, he_gk);
    evaluator.multiply_plain(state, matrix[i], tmp);
    evaluator.add_inplace(sum, tmp);
  }
  state = sum;
}

//----------------------------------------------------------------

void PASTA_SEAL::mix(seal::Ciphertext& state) {
  seal::Ciphertext tmp;
  evaluator.rotate_columns(state, he_gk, tmp);
  evaluator.add_inplace(tmp, state);
  evaluator.add_inplace(state, tmp);
}

}  // namespace PASTA_4
