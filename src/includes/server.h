#pragma once
#include "seal/seal.h"
#include <cstdint>

using namespace seal;
// We initialize a server with a given SEALContext.
// Servers compute z, the encrypted equality function.
class Server {
public:
  
  // Initializes server with given parameters
  Server(EncryptionParameters parameters, SEALContext context) :
    parameters(parameters), 
    context(context),
    evaluator(Evaluator(context))
     {};

  Ciphertext compute_z(Ciphertext x, uint64_t y);

private:
  EncryptionParameters parameters;
  SEALContext context;
  Evaluator evaluator;
};