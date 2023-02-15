#pragma once
#include "seal/seal.h"
#include <cstdint>
#include <vector>
#include "client.h"
#include "cwc.h"

using namespace seal;
/*
  Servers are initialized with a client context. Servers store their database as a map from uint64_t to uint64_t.
*/
class Server {
public:
  
  // For testing
  Decryptor * decryptor = nullptr;


  // Initialize the server with a client.
  Server(ClientContext &client_context) :
    client_context(client_context),
    evaluator(Evaluator(client_context.context))
    {};

  void set_database(std::map<uint64_t,uint64_t> new_db);
  
  // Expands query using algorithm 5
  std::vector<Ciphertext> expand_query(Query query);
  
  // Expands query using seal pir's oblivious expansion algorithm.
  std::vector<Ciphertext> sealpir_expand_query(Query query);
  
  // Algorithm 6
  std::map<uint64_t, Ciphertext> get_selection_vector(std::vector<Ciphertext> expanded_query);

  Ciphertext calculate_inner_product(std::map<uint64_t, Ciphertext> selection_vector);

  // Returns the result to a query
  Ciphertext make_query(Query query);


private:
  ClientContext client_context;
  std::vector<uint64_t> y_vals;
  std::vector<Ciphertext> z_vals;
  Evaluator evaluator;
  std::map<uint64_t,uint64_t> database;
  

  void shift_polynomial(Ciphertext & encrypted, Ciphertext & destination, size_t index);
};
