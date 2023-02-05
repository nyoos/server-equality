#include "server.h"
#include "utils.h"

// We compute the encrypted equality function by adding the additive inverse of y to x'.
Ciphertext Server::compute_z (Ciphertext x, uint64_t y){
  uint64_t plaintext_modulus = parameters.plain_modulus().value();
  uint64_t y_complement = plaintext_modulus - y;
  Plaintext y_plain(uint_to_hex_string(y_complement));
  evaluator.add_plain_inplace(x, y_plain);
  return x;
}