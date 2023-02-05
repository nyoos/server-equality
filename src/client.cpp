#include "client.h"
#include "utils.h"
#include <string>
#include <iostream>

bool Client::is_zero(Ciphertext z_encrypted) {
  Plaintext z_decrypted;
  decryptor.decrypt(z_encrypted, z_decrypted);
  std::string output = z_decrypted.to_string();
  uint64_t result = hex_string_to_uint(output);
  return result == 0;
}

uint64_t Client::decrypt(Ciphertext x_encrypted) {
  Plaintext x_plain;
  decryptor.decrypt(x_encrypted, x_plain);
  std::string output = x_plain.to_string();
  uint64_t result = hex_string_to_uint(output);
  return result;
}

Ciphertext Client::set_x(uint64_t new_x) {
  x = new_x;
  Plaintext x_plain(uint_to_hex_string(x));
  Ciphertext x_encrypted;
  encryptor.encrypt(x_plain, x_encrypted);
  return x_encrypted;
}

EncryptionParameters Client::get_parameters() {
  return parameters;
}

SEALContext Client::get_context() {
  return context;
}
int Client::check_noise(Ciphertext x) {
  return decryptor.invariant_noise_budget(x);
}