#include "client.h"
#include "cwc.h"
#include <string>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <cmath>


// 2^c = poly_degree
Query Client::generate_query(uint64_t x) {

  std::vector<size_t> x_eles = perfect_mapping(x, bit_length, hamming_weight);
  uint64_t poly_degree = parameters.poly_modulus_degree();
  uint64_t num_ciphertexts = bit_length / poly_degree + bit_length % poly_degree;
  std::vector<Plaintext> plaintexts;

  for (int i = 0; i < num_ciphertexts; i++) {
    plaintexts.push_back(Plaintext(poly_degree));
  }
  uint64_t inverse = 0;
  util::try_invert_uint_mod(poly_degree, parameters.plain_modulus(), inverse);
 
  for (size_t & index : x_eles) {
    plaintexts[index / poly_degree][index % poly_degree] = inverse;
  }
  
  Query query;
  for (int i = 0; i < num_ciphertexts; i++) {
    Ciphertext x_encrypted;
    encryptor.encrypt(plaintexts[i], x_encrypted);
    query.push_back(x_encrypted);
  }
  return query;
}


ClientContext Client::get_context() {
  ClientContext result = {parameters,context,public_key,galois_keys,relin_keys,hamming_weight,bit_length};
  return result;
}

Decryptor * Client::get_decryptor(){
  return &decryptor;
}

int Client::check_noise(Ciphertext x) {
  return decryptor.invariant_noise_budget(x);
}

void Client::test(){

  Plaintext z("1");
  std::cout <<z.to_string() << std::endl;
  Query query = generate_query(1);

  std::cout <<"query generated successfully"<< std::endl;
  for (auto & i : query) {
    decryptor.decrypt(i, z);
    std::cout <<z.to_string() << std::endl;

  }
}