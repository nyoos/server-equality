#pragma once
#include "seal/seal.h"
#include <vector>
#include <cstdint>

using namespace seal;

// Initialize a client with encryption parameters. 
// Clients can encrypt numbers and check if a decrypted number is 0.
class Client {
public:

  // Use a factory function since initialization is complex.
  // Validates parameters, generates context and keys.
  static Client create(size_t polynomial_modulus, size_t plaintext_modulus) {
    EncryptionParameters parameters(scheme_type::bfv);
    parameters.set_poly_modulus_degree(polynomial_modulus);
    parameters.set_coeff_modulus(CoeffModulus::BFVDefault(polynomial_modulus));
    parameters.set_plain_modulus(plaintext_modulus);
    SEALContext context(parameters);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    return Client(parameters, context, public_key, secret_key);
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
    keygen.create_public_key(public_key);
    return Client(parameters, context, public_key, secret_key);
  };
  bool is_zero(Ciphertext z_encrypted);
  Ciphertext set_x(uint64_t x);

  EncryptionParameters get_parameters();
  SEALContext get_context();

  // For testing
  int check_noise(Ciphertext x);
private:
  EncryptionParameters parameters;
  SEALContext context;
  PublicKey public_key;
  Encryptor encryptor;
  Decryptor decryptor;
  uint64_t x = 0;
  
  Client(EncryptionParameters parameters, SEALContext context, PublicKey public_key, SecretKey secret_key) :
    parameters(parameters),
    context(context),
    public_key(public_key),
    encryptor(Encryptor(context, public_key)),
    decryptor(Decryptor(context, secret_key))
    {};

  void encrypt_x();
  uint64_t decrypt(Ciphertext x_encrypted) ;
};