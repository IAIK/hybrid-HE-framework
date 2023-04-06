#pragma once

#include <cstddef>
#include <stdint.h>

#include <vector>

namespace matrix {
typedef std::vector<uint64_t> vector;
typedef std::vector<std::vector<uint64_t>> matrix;

static void matMul(vector& vo, const matrix& M, const vector& vi,
                   size_t bitsize) {
  const uint64_t mask = (1ULL << bitsize) - 1;
  size_t cols = vi.size();
  size_t rows = M.size();

  if (vo.size() != rows) vo.resize(rows);

  for (size_t row = 0; row < rows; row++) {
    vo[row] = (vi[0] * M[row][0]) & mask;
    for (size_t col = 1; col < cols; col++) {
      vo[row] += (vi[col] * M[row][col]) & mask;
      vo[row] &= mask;
    }
  }
}

// vo = vi + b
static void vecAdd(vector& vo, const vector& vi, const vector& b,
                   size_t bitsize) {
  const uint64_t mask = (1ULL << bitsize) - 1;
  size_t rows = vi.size();
  if (vo.size() != rows) vo.resize(rows);

  for (size_t row = 0; row < vi.size(); row++)
    vo[row] = (vi[row] + b[row]) & mask;
}

// vo = M * vi + b
static void affine(vector& vo, const matrix& M, const vector& vi,
                   const vector& b, size_t bitsize) {
  matMul(vo, M, vi, bitsize);
  vecAdd(vo, vo, b, bitsize);
}
}  // namespace matrix
