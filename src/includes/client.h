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
};
class Client {
public:
  int hamming_weight = 2;
  int bit_length = 4096;

  // Use a factory function since initialization is complex.
  // Validates parameters, generates context and keys.
  // Generates galois keys for indexes 2^0 + 1, 2^1 + 1, ... poly_mod + 1
  static Client create(size_t polynomial_modulus, size_t plaintext_modulus) {
    return create(polynomial_modulus, plaintext_modulus, CoeffModulus::BFVDefault(polynomial_modulus));
  };
  
  static Client create(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coefficient_modulus) {
    EncryptionParameters parameters(scheme_type::bfv);
    parameters.set_poly_modulus_degree(polynomial_modulus);
    parameters.set_coeff_modulus(coefficient_modulus);
    parameters.set_plain_modulus(plaintext_modulus);
    SEALContext context(parameters);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    std::vector<uint32_t> galois_elts = {1};
    // for (size_t i = 1; i < polynomial_modulus * 2 ; i += 2) {
    //     galois_elts.push_back(i);
    // }
    for (size_t i = 3; i <= polynomial_modulus + 1 ; i = (i-1)*2 + 1) {
        galois_elts.push_back(i);
    }
    GaloisKeys galois_keys;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_galois_keys(galois_elts,galois_keys);
    keygen.create_relin_keys(relin_keys);
    return Client(parameters, context, public_key, galois_keys, relin_keys, secret_key);
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
  
  Client(EncryptionParameters parameters, SEALContext context, PublicKey public_key, GaloisKeys galois_keys, RelinKeys relin_keys, SecretKey secret_key) :
    parameters(parameters),
    context(context),
    public_key(public_key),
    galois_keys(galois_keys),
    relin_keys(relin_keys),
    encryptor(Encryptor(context, public_key)),
    decryptor(Decryptor(context, secret_key))
    {};

};