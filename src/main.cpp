#include <stdio.h>
#include <iostream>
#include <vector>
#include <random>
#include "client.h"
#include "test_bench.h"
#include "server.h"
#include "seal/seal.h"
#include "cwc.h"
#include <climits>

using namespace seal;

void print_vector(std::vector<uint64_t> & m) {
    for (auto & i : m) {
        std::cout << i << " ";
    }
    std::cout << std::endl;
}

void print_ciphertext_vec(std::vector<Ciphertext> &v, Decryptor * decryptor) {
    Plaintext plain;
    for (auto & c: v) {
        decryptor->decrypt(c, plain);
        std::cout << plain.to_string() << " || ";
    }
    std::cout << std::endl;
}

int main(int argc, char *argv[]){

    // Running the test cases (when the 0 flag is not passed) consumes a lot of memory - may cause computer to crash
    if (argc == 2 && argv[1][0] == '0'){
        Client client = Client::create(4096, 65);
        client.bit_length = 4096;
        client.hamming_weight = 2;
        ClientContext client_context = client.get_context();
        Server server(client_context);
        Decryptor * decryptor = client.get_decryptor();
        server.decryptor = decryptor;

        std::map<uint64_t,uint64_t> database = {{1,1},
                                    {2,4},
                                    {3,9},
                                    {5,25},
                                    {7, 49},
                                    {101, 64},
                                    };
                                    
        server.set_database(database);

        Query query = client.generate_query(5);
        print_ciphertext_vec(query,decryptor);
        Ciphertext query_result = server.make_query(query);

        // std::map<uint64_t,Ciphertext> selvec = server.get_selection_vector(res);
        // Plaintext plain;
        // for (auto const &[key, value] : selvec) {
        //     decryptor->decrypt(value, plain);
        //     std::cout << key << ": " << plain.to_string() << std::endl;
        // }

        // Ciphertext query_result = server.calculate_inner_product(selvec);
        Plaintext plain_result;
        decryptor->decrypt(query_result, plain_result);
        std::cout << "Query result:" << plain_result.to_string() << std::endl;

        
        return 0;
    }

        // Consumes a lot of memory - may cause computer to crash
        std::vector<std::vector<int>> results;
        std::vector<int> polynomial_mods = {4096, 8192};
        std::vector<int> plaintext_mods = {65, 129};
        std::vector<int> hamming_weights = {2,3,4,5};
        for (auto polynomial_mod : polynomial_mods) {
            for (auto plaintext_mod : plaintext_mods) {
                for (auto hamming_weight : hamming_weights) {
                    Client client = Client::create(polynomial_mod, plaintext_mod);
                    client.bit_length = polynomial_mod;
                    client.hamming_weight = hamming_weight;
                    ClientContext client_context = client.get_context();
                    Server server(client_context);
                    Decryptor * decryptor = client.get_decryptor();
                    server.decryptor = decryptor;

                    std::map<uint64_t,uint64_t> database = {{1,1},
                                                {2,4},
                                                };
                                                
                    server.set_database(database);
                    Query query = client.generate_query(2);
                    print_ciphertext_vec(query,decryptor);
                    Ciphertext query_result = server.make_query(query);
                    int noise = decryptor->invariant_noise_budget(query_result);
                    std::vector<int> result = {polynomial_mod, plaintext_mod, hamming_weight, noise};
                    results.push_back(result);
                }
            }
        }

        for (int i = 0; i < results.size(); i++) {
            std::cout << "polynomial mod: " << results[i][0] << " plaintext_mod: " << results[i][1] << " hamming_weight: " << results[i][2] << " noise_budget: " << results[i][3] << std::endl;
        }


    return 0;
}