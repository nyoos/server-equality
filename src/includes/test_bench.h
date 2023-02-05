#pragma once
#include <string>
#include <vector>
#include "seal/seal.h"

using namespace seal;

double overall_timing_test(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coeff_modulus);
double encryption_timing_test(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coeff_modulus);
double decryption_timing_test(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coeff_modulus);
double computation_timing_test(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coeff_modulus);
std::vector<int> overall_noise_test(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coeff_modulus);
