#pragma once
#include <vector>
#include "seal/seal.h"

using namespace seal;
using namespace seal::util;

typedef std::vector<Ciphertext> Query;

std::vector<size_t> perfect_mapping(int x, int bitlength, int weight);
long long binomial(int n, int k);
void negacyclic_shift_poly_coeffmod(ConstCoeffIter poly, size_t coeff_count, size_t shift, const Modulus &modulus, CoeffIter result);