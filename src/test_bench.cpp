#include <iostream>
#include <cstdint>
#include <chrono>
#include <random>
#include <sstream>
#include <vector>
#include "seal/seal.h"
#include "client.h"
#include "server.h"
#include "test_bench.h"

// #define SAMPLE_SIZE 1
#define Y_PER_X 2
#define RAND_SEED 1

using namespace seal;


// Returns a vector of the noise budget after a {fresh encryption, computation}
std::vector<int> overall_noise_test(size_t polynomial_modulus, size_t plaintext_modulus){

    std::vector<int> result;
    // Generate random test data.
    std::mt19937 random_generator(RAND_SEED);
    std::uniform_int_distribution<> distrib(0, polynomial_modulus/2 - 1);

    // Set parameters
    Client client = Client::create(polynomial_modulus, plaintext_modulus);
    Server server(client);

    Ciphertext x_encrypted;
    uint64_t x = distrib(random_generator);
    std::vector<uint64_t> y_s;
    y_s.push_back(x);
    for (int j = 1; j < Y_PER_X; j++) {
        y_s.push_back(distrib(random_generator));
    }
    x_encrypted = client.set_x(x);
    result.push_back(client.check_noise(x_encrypted));
    server.set_y(y_s);
    server.compute_z(x_encrypted);
    result.push_back(server.get_noise());
    return result;
}


double overall_timing_test(size_t polynomial_modulus, size_t plaintext_modulus){
    std::cout << "====== \nPolynomial modulus: " << polynomial_modulus << "\t|| Plaintext modulus: " <<plaintext_modulus<<std::endl;  

    // Generate random test data. One of the y's will correspond to the x. 
    std::mt19937 random_generator(RAND_SEED);
    std::uniform_int_distribution<> distrib(0, polynomial_modulus/2-1);
    uint64_t x ;
    std::vector<uint64_t> y_s;
    x= distrib(random_generator);
    y_s.push_back(x);
    for (int j = 1; j < Y_PER_X; j++) {
        y_s.push_back(distrib(random_generator));
    }

    // Set parameters
    Client client = Client::create(polynomial_modulus, plaintext_modulus);
    Server server(client);

    Ciphertext x_encrypted;
    Ciphertext z_encrypted;
    uint64_t y;
    

    std::cout << "-------" <<std::endl;
    // Begin test
    auto start = std::chrono::high_resolution_clock::now();

    x_encrypted = client.set_x(x);
    server.set_y(y_s);
    server.compute_z(x_encrypted);

    auto elapsed= std::chrono::high_resolution_clock::now() - start;
    // End test
    double microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            elapsed).count();
    double time_per_test = microseconds;
    std::cout << "Took a total of " << microseconds << " microseconds for len(y) = " << Y_PER_X << "." << std::endl;
    return time_per_test;
}

double encryption_timing_test(size_t polynomial_modulus, size_t plaintext_modulus) {
    std::cout << "====== \nPolynomial modulus: " << polynomial_modulus << "\t|| Plaintext modulus: " <<plaintext_modulus<<std::endl;  

    // Generate random test data. 
    std::mt19937 random_generator(RAND_SEED);
    std::uniform_int_distribution<> distrib(0, polynomial_modulus/2-1);
    uint64_t x ;
    std::vector<uint64_t> y_s;
    x= distrib(random_generator);
    y_s.push_back(x);
    for (int j = 1; j < Y_PER_X; j++) {
        y_s.push_back(distrib(random_generator));
    }

    // Initialize client
    Client client = Client::create(polynomial_modulus, plaintext_modulus);

    std::cout << "-------" <<std::endl;
    // Begin test
    auto start = std::chrono::high_resolution_clock::now();

        client.set_x(x);

    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    // End test
    double microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            elapsed).count();
    double time_per_test = microseconds;
    std::cout << "Took a total of " << microseconds << " microseconds."<< std::endl;
    return time_per_test;
}


double computation_timing_test(size_t polynomial_modulus, size_t plaintext_modulus) {
    std::cout << "====== \nPolynomial modulus: " << polynomial_modulus << "\t|| Plaintext modulus: " <<plaintext_modulus<<std::endl;  

    // Generate random test data. One of the y's will correspond to the x. 
    std::mt19937 random_generator(RAND_SEED);
    std::uniform_int_distribution<> distrib(0, polynomial_modulus/2-1);
    uint64_t x ;
    std::vector<uint64_t> y_s;
    x= distrib(random_generator);
    y_s.push_back(x);
    for (int j = 1; j < Y_PER_X; j++) {
        y_s.push_back(distrib(random_generator));
    }

    // Set parameters
    Client client = Client::create(polynomial_modulus, plaintext_modulus);
    Server server(client);

    // Set up encrypted xs for computation 
    Ciphertext x_encrypted = client.set_x(x);
    server.set_y(y_s);

    std::cout << "-------" <<std::endl;
    // Begin test
    auto start = std::chrono::high_resolution_clock::now();
    server.compute_z(x_encrypted);

    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    // End test
    double microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            elapsed).count();
    double time_per_test = microseconds ;
    std::cout << "Took a total of " << microseconds << " microseconds for len(y_arr) = " << Y_PER_X << "." << std::endl;
    return time_per_test;
}