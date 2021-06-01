#pragma once

#include <stdint.h>

#include <vector>

namespace matrix {
typedef std::vector<uint64_t> vector;
typedef std::vector<std::vector<uint64_t>> matrix;
typedef __uint128_t uint128_t;

static void matMul(vector& vo, const matrix& M, const vector& vi,
                   size_t modulus) {
  size_t cols = vi.size();
  size_t rows = M.size();

  if (vo.size() != rows) vo.resize(rows);

  for (size_t row = 0; row < rows; row++) {
    vo[row] = (((uint128_t)vi[0]) * M[row][0]) % modulus;
    for (size_t col = 1; col < cols; col++) {
      vo[row] += ((((uint128_t)vi[col]) * M[row][col]) % modulus);
      vo[row] %= modulus;
    }
  }
}

// vo = vi + b
static void vecAdd(vector& vo, const vector& vi, const vector& b,
                   size_t modulus) {
  size_t rows = vi.size();
  if (vo.size() != rows) vo.resize(rows);

  for (size_t row = 0; row < vi.size(); row++)
    vo[row] = (vi[row] + b[row]) % modulus;
}

// vo = M * vi + b
static void affine(vector& vo, const matrix& M, const vector& vi,
                   const vector& b, size_t modulus) {
  matMul(vo, M, vi, modulus);
  vecAdd(vo, vo, b, modulus);
}

// vo = M * vi + b
static void square(vector& vo, const vector& vi, size_t modulus) {
  size_t rows = vi.size();
  if (vo.size() != rows) vo.resize(rows);

  for (size_t row = 0; row < vi.size(); row++)
    vo[row] = ((((uint128_t)vi[row]) * vi[row]) % modulus);
}

}  // namespace matrix
