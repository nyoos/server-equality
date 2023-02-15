#define __STDCPP_WANT_MATH_SPEC_FUNCS__ 1
#include "cwc.h"
#include <cmath>
#include <stdexcept>

using namespace seal::util;
// Returns the indexes of the bits that should be set to 1. Uses algorithm 3.
std::vector<size_t> perfect_mapping(int x, int bitlength, int weight){
  long long max = binomial(bitlength, weight);
  if (x > max - 1) {
    throw std::invalid_argument("x is outside the range.");
  }
  std::vector<size_t> result;
  for(int m = bitlength-1; m >= 0; --m) {
    if (x >= binomial(m,weight)) {
      result.push_back(m);
      x -= binomial(m,weight);
      weight -= 1;
    }
    if (weight ==0) return result;
  }
  return result;
}

// Utility to calculate n choose k.
long long binomial(int n, int k) {
  return lround(1/((n+1)*std::beta(n-k+1,k+1)));
}

// Was unable to access this, so have made a copy as a temporary solution.
void negacyclic_shift_poly_coeffmod(ConstCoeffIter poly, size_t coeff_count, size_t shift, const Modulus &modulus, CoeffIter result){
  // Nothing to do
  if (shift == 0)
  {
      set_uint(poly, coeff_count, result);
      return;
  }

  uint64_t index_raw = shift;
  uint64_t coeff_count_mod_mask = static_cast<uint64_t>(coeff_count) - 1;
  for (size_t i = 0; i < coeff_count; i++, poly++, index_raw++)
  {
      uint64_t index = index_raw & coeff_count_mod_mask;
      if (!(index_raw & static_cast<uint64_t>(coeff_count)) || !*poly)
      {
          result[index] = *poly;
      }
      else
      {
          result[index] = modulus.value() - *poly;
      }
  }
}
