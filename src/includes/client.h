#pragma once
#include "seal/seal.h"
#include <vector>
#include <cstdint>
#include "cwc.h"

using namespace seal;

/*
Initialize a client with encryption parameters. 
The plaintext modulus must be relatively prime to the polynomial degree modulus to work.
Clients build SEALContext and generate public, galois and relinearization keys.
*/

struct ClientContext {
  EncryptionParameters parameters;
  SEALContext context;
  PublicKey public_key;
  GaloisKeys galois_keys;
  RelinKeys relin_keys;
  int hamming_weight;
  int bit_length;
  int compression_factor;
};
class Client {
public:
  // Hamming_weight and bit_length are the parameters of the constant code word encoding. Bit length must be a power of 2.
  int hamming_weight = 2;
  int bit_length = 4096;

  // Compression factor determines how many bits there are per message (and hence the total query size), with bits per message = 2^compression_factor. 
  // For example, with compression factor = 11 and bit length = 4096, we end up with 2048 bits per message and a total query size of 2. 
  // The 2048 bits will be encoded in the first 2048 coeffs of the polynomial.
  // 2^compression_factor must be less than or equal to polynomial modulus degree and bit_length.
  int compression_factor = 12;

  // Use a factory function since initialization is complex.
  // Validates parameters, generates context and keys.
  // Generates galois keys for indexes 2^0 + 1, 2^1 + 1, ... poly_mod + 1
  static Client create(size_t polynomial_modulus, size_t plaintext_modulus, int hamming_weight, int bit_length, int compression_factor) {
    return create(polynomial_modulus, plaintext_modulus, CoeffModulus::BFVDefault(polynomial_modulus), hamming_weight, bit_length, compression_factor);
  };
  
  static Client create(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coefficient_modulus, int hamming_weight, int bit_length, int compression_factor) {
    EncryptionParameters parameters(scheme_type::bfv);
    parameters.set_poly_modulus_degree(polynomial_modulus);
    parameters.set_coeff_modulus(coefficient_modulus);
    parameters.set_plain_modulus(plaintext_modulus);
    SEALContext context(parameters);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    std::vector<uint32_t> galois_elts = {1};
    size_t min_ele = polynomial_modulus/pow(2,compression_factor) + 1;
    for (size_t i = min_ele; i <= polynomial_modulus + 1 ; i = (i-1)*2 + 1) {
        galois_elts.push_back(i);
    }
    GaloisKeys galois_keys;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_galois_keys(galois_elts,galois_keys);
    keygen.create_relin_keys(relin_keys);
    return Client(parameters, context, public_key, galois_keys, relin_keys, secret_key, hamming_weight, bit_length, compression_factor);
  };

  ClientContext get_context();
  Query generate_query(uint64_t x);

  // For testing
  int check_noise(Ciphertext x);
  Decryptor * get_decryptor();
  void test();
private:
  EncryptionParameters parameters;
  SEALContext context;
  PublicKey public_key;
  GaloisKeys galois_keys;
  Encryptor encryptor;
  Decryptor decryptor;
  RelinKeys relin_keys;
  uint64_t x = 0;
  
  Client(EncryptionParameters parameters, SEALContext context, PublicKey public_key, GaloisKeys galois_keys, RelinKeys relin_keys, SecretKey secret_key, int hamming_weight, int bit_length, int compression_factor) :
    parameters(parameters),
    context(context),
    public_key(public_key),
    galois_keys(galois_keys),
    relin_keys(relin_keys),
    encryptor(Encryptor(context, public_key)),
    decryptor(Decryptor(context, secret_key)),
    hamming_weight(hamming_weight),
    bit_length(bit_length),
    compression_factor(compression_factor)
    {};

};