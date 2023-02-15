#include "server.h"
#include "utils.h"
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include "cwc.h"
#include <cmath>

std::vector<Ciphertext> Server::expand_query(Query query) {
  std::vector<Ciphertext> expanded_query;
  int poly_degree = client_context.parameters.poly_modulus_degree();
  int c = std::log2(poly_degree);

  for (size_t j = 0; j < query.size(); j++) {
    std::vector<Ciphertext> cipher_vec(poly_degree);
    cipher_vec[0] = query[j];

    for (size_t a = 0; a < c; a++) {

      int expansion_factor = pow(2, a);
      for (size_t b = 0; b < expansion_factor; b++) {
        Ciphertext cipher0 = cipher_vec[b];
        evaluator.apply_galois_inplace(cipher0,
                                       poly_degree/expansion_factor + 1,
                                       client_context.galois_keys);
        Ciphertext cipher1;
        shift_polynomial(cipher0, cipher1, -expansion_factor);
        shift_polynomial(cipher_vec[b], cipher_vec[b + expansion_factor], -expansion_factor);
        evaluator.add_inplace(cipher_vec[b], cipher0);
        evaluator.sub_inplace(cipher_vec[b + expansion_factor], cipher1);
      }
      // Show the expansion
      Plaintext plain;
      for (int i = 0; i < pow(2,a); i++) {
          decryptor->decrypt(cipher_vec[i], plain);
          std::cout << plain.to_string() << "|| " ;
      }
      std::cout << std::endl;
    }

    expanded_query.reserve(expanded_query.size() + cipher_vec.size());
    expanded_query.insert(expanded_query.end(), std::make_move_iterator(cipher_vec.begin()), std::make_move_iterator(cipher_vec.end()));
  }

  return expanded_query;
}

// This implementation only works with compression = log_2 N, i.e. when size of query = 1
std::vector<Ciphertext> Server::sealpir_expand_query(Query query) {
  std::vector<Ciphertext> expanded_query(query);
  for (int i = expanded_query.size(); i < client_context.bit_length; i++) {
    expanded_query.push_back(Ciphertext());
  }
  int poly_degree = client_context.parameters.poly_modulus_degree();
  int c = std::log2(poly_degree);

  std::cout << "Expanded query size:" << expanded_query.size()<< std::endl;
    for (int j = 0; j < c; j++) {

      // Show the expansion
      Plaintext plain;
      for (int i = 0; i < pow(2,j); i++) {
          decryptor->decrypt(expanded_query[i], plain);
          std::cout << plain.to_string() << "|| " ;
      }
      std::cout << std::endl;

      int expansion_factor = pow(2,j);
      for (int k = 0; k < expansion_factor; k++){

        Ciphertext cipher0 = expanded_query[k];
        Ciphertext cipher1;
        shift_polynomial(cipher0, cipher1, -expansion_factor);
        Ciphertext cipher2, cipher3;
        
        evaluator.apply_galois(cipher0, 
                               poly_degree/expansion_factor + 1,
                               client_context.galois_keys,
                               cipher2);
        evaluator.add_inplace(cipher2, cipher0);
        expanded_query[k] = cipher2;

        evaluator.apply_galois(cipher1, 
                               poly_degree/expansion_factor + 1,
                               client_context.galois_keys,
                               cipher3);
        evaluator.add_inplace(cipher3, cipher1);
        expanded_query[k + expansion_factor] = cipher3;
      }
    }
  return expanded_query;
}

std::map<uint64_t, Ciphertext> Server::get_selection_vector(std::vector<Ciphertext> expanded_query){
  std::map<uint64_t, Ciphertext> selection_vector;
  for (const auto& [key, value] : database) {
    std::vector<size_t> cwc = perfect_mapping(key, client_context.bit_length, client_context.hamming_weight);
    Ciphertext bit;
    std::vector<Ciphertext> to_multiply;
    for(size_t & index : cwc) {
      to_multiply.push_back(expanded_query[index]);
    }
    evaluator.multiply_many(to_multiply, client_context.relin_keys, bit);
    selection_vector.insert({key,bit});
  }
  return selection_vector;
}

Ciphertext Server::calculate_inner_product(std::map<uint64_t, Ciphertext> selection_vector) {
  std::vector<Ciphertext> cipher_vec;
  for(const auto & [key,value] : selection_vector){
    Plaintext database_value_plain(util::uint_to_hex_string(&database[key], 1));
    Ciphertext temp;
    Plaintext plain;
    decryptor->decrypt(value, plain);
    std::cout << "selection vector element:" << plain.to_string() << std::endl;
    std::cout << "database value: " << database_value_plain.to_string() << std::endl;
    std::cout << "noise budget: " << decryptor->invariant_noise_budget(value) <<std::endl;
    evaluator.multiply_plain(value,database_value_plain, temp);
    evaluator.relinearize_inplace(temp, client_context.relin_keys);
    
    decryptor->decrypt(temp, plain);
    std::cout << "result: " << plain.to_string() << std::endl;
    std::cout << std::endl;
    cipher_vec.push_back(temp);
  }
  Ciphertext result;
  evaluator.add_many(cipher_vec, result);
  std::cout << "noise budget: " << decryptor->invariant_noise_budget(result) <<std::endl;
  return result;
}


void Server::set_database(std::map<uint64_t,uint64_t> new_db){
  database = new_db;
}

void Server::shift_polynomial(Ciphertext & encrypted, Ciphertext & destination, size_t index){
  auto encrypted_count = encrypted.size();
  auto coeff_count = client_context.parameters.poly_modulus_degree();
  auto coeff_mod_count = client_context.parameters.coeff_modulus().size() - 1;
  destination = encrypted;
  for (int i = 0; i < encrypted_count; i++) {
    for (int j = 0; j < coeff_mod_count; j++) {
      negacyclic_shift_poly_coeffmod(encrypted.data(i) + (j * coeff_count),
                                     coeff_count, index,
                                     client_context.parameters.coeff_modulus()[j],
                                     destination.data(i) + (j * coeff_count));
    }
  }
}

Ciphertext Server::make_query(Query query) {
  std::vector<Ciphertext> expanded_query = expand_query(query);
  std::map<uint64_t,Ciphertext> selection_vector = get_selection_vector(expanded_query);
  Ciphertext query_result = calculate_inner_product(selection_vector);
  return query_result;
}


