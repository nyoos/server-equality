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

#define SAMPLE_SIZE 1
#define Y_PER_X 1
#define RAND_SEED 1

using namespace seal;

// We test with random integers from 0 to the plaintext_modulus. We record the time taken to perform 
// sample size * y per x number of tests and divide to get the time for each test.
// Returns a vector of the noise budget after a {fresh encryption, computation}
std::vector<int> overall_noise_test(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coeff_modulus){

    std::vector<int> result;
    // Generate random test data.
    std::mt19937 random_generator(RAND_SEED);
    std::uniform_int_distribution<> distrib(0, plaintext_modulus-1);

    // Set parameters
    Client client = Client::create(polynomial_modulus, plaintext_modulus,coeff_modulus);
    Server server(client.get_parameters(), client.get_context());

    Ciphertext x_encrypted;
    Ciphertext z_encrypted;
    uint64_t x = distrib(random_generator);
    uint64_t y = distrib(random_generator);
    x_encrypted = client.set_x(x);
    result.push_back(client.check_noise(x_encrypted));
    z_encrypted = server.compute_z(x_encrypted,y);
    result.push_back(client.check_noise(z_encrypted));

    
    return result;
}

double overall_timing_test(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coeff_modulus){
    std::cout << "====== \nPolynomial modulus: " << polynomial_modulus << "\t|| Plaintext modulus: " <<plaintext_modulus<<std::endl;  

    // Generate random test data. One of the y's will correspond to the x. 
    std::mt19937 random_generator(RAND_SEED);
    std::uniform_int_distribution<> distrib(0, plaintext_modulus-1);
    uint64_t x_s [SAMPLE_SIZE];
    uint64_t y_s [SAMPLE_SIZE*Y_PER_X];
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        x_s[i] = distrib(random_generator);
        y_s[i * Y_PER_X] = x_s[i];
        for (int j = 1; j < Y_PER_X; j++) {
            y_s[i * Y_PER_X +j] = distrib(random_generator);
        }
    }

    // Set parameters
    Client client = Client::create(polynomial_modulus, plaintext_modulus, coeff_modulus);
    Server server(client.get_parameters(), client.get_context());

    Ciphertext x_encrypted;
    Ciphertext z_encrypted;
    uint64_t x = x_s[0];
    uint64_t y;
    

    std::cout << "-------" <<std::endl;
    // Begin test
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < SAMPLE_SIZE; i++) {
        x_encrypted = client.set_x(x_s[i]);
        for (int j = 0; j < Y_PER_X; j++) {
            z_encrypted = server.compute_z(x_encrypted, y_s[i * Y_PER_X + j]);
            client.is_zero(z_encrypted);
        }
    }

    auto elapsed= std::chrono::high_resolution_clock::now() - start;
    // End test
    double microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            elapsed).count();
    double time_per_test = microseconds / (double) (SAMPLE_SIZE * Y_PER_X) ;
    std::cout << "Took a total of " << microseconds << " microseconds for " << SAMPLE_SIZE*Y_PER_X << " tests." << std::endl;
    std::cout << "Time per test: " << time_per_test << " microseconds." << std::endl;;
    return time_per_test;
}

double encryption_timing_test(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coeff_modulus) {
    std::cout << "====== \nPolynomial modulus: " << polynomial_modulus << "\t|| Plaintext modulus: " <<plaintext_modulus<<std::endl;  

    // Generate random test data. 
    std::mt19937 random_generator(RAND_SEED);
    std::uniform_int_distribution<> distrib(0, plaintext_modulus-1);
    uint64_t x_s [SAMPLE_SIZE];
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        x_s[i] = distrib(random_generator);
    }

    // Initialize client
    Client client = Client::create(polynomial_modulus, plaintext_modulus, coeff_modulus);
    uint64_t x = x_s[0];

    std::cout << "-------" <<std::endl;
    // Begin test
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < SAMPLE_SIZE; i++) {
        client.set_x(x_s[i]);
    }

    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    // End test
    double microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            elapsed).count();
    double time_per_test = microseconds / (double) (SAMPLE_SIZE) ;
    std::cout << "Took a total of " << microseconds << " microseconds for " << SAMPLE_SIZE*Y_PER_X << " tests." << std::endl;
    std::cout << "Time per test: " << time_per_test << " microseconds." << std::endl;;
    return time_per_test;
}

double decryption_timing_test(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coeff_modulus) {
    std::cout << "====== \nPolynomial modulus: " << polynomial_modulus << "\t|| Plaintext modulus: " <<plaintext_modulus<<std::endl;  

    // Generate random test data. One of the y's will correspond to the x. 
    std::mt19937 random_generator(RAND_SEED);
    std::uniform_int_distribution<> distrib(0, plaintext_modulus-1);
    uint64_t x_s [SAMPLE_SIZE];
    uint64_t y_s [SAMPLE_SIZE*Y_PER_X];
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        x_s[i] = distrib(random_generator);
        y_s[i * Y_PER_X] = x_s[i];
        for (int j = 1; j < Y_PER_X; j++) {
            y_s[i * Y_PER_X +j] = distrib(random_generator);
        }
    }

    // Set parameters
    Client client = Client::create(polynomial_modulus, plaintext_modulus, coeff_modulus);
    Server server(client.get_parameters(), client.get_context());

    // Set up zs for decryption
    Ciphertext x_encrypted;
    Ciphertext z_encrypted_arr [SAMPLE_SIZE * Y_PER_X];
    uint64_t x = x_s[0];
    uint64_t y;
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        x_encrypted = client.set_x(x_s[i]);
        for (int j = 0; j < Y_PER_X; j++) {
            z_encrypted_arr[i*Y_PER_X + j] = server.compute_z(x_encrypted, y_s[i * Y_PER_X + j]);
        }
    }
    

    std::cout << "-------" <<std::endl;
    // Begin test
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < SAMPLE_SIZE; i++) {
        for (int j = 0; j < Y_PER_X; j++) {
            client.is_zero(z_encrypted_arr[i*Y_PER_X + j]);
        }
    }

    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    // End test
    double microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            elapsed).count();
    double time_per_test = microseconds / (double) (SAMPLE_SIZE * Y_PER_X) ;
    std::cout << "Took a total of " << microseconds << " microseconds for " << SAMPLE_SIZE*Y_PER_X << " tests." << std::endl;
    std::cout << "Time per test: " << time_per_test << " microseconds." << std::endl;;
    return time_per_test;
}

double computation_timing_test(size_t polynomial_modulus, size_t plaintext_modulus, std::vector<Modulus> coeff_modulus) {
    std::cout << "====== \nPolynomial modulus: " << polynomial_modulus << "\t|| Plaintext modulus: " <<plaintext_modulus<<std::endl;  

    // Generate random test data. One of the y's will correspond to the x. 
    std::mt19937 random_generator(RAND_SEED);
    std::uniform_int_distribution<> distrib(0, plaintext_modulus-1);
    uint64_t x_s [SAMPLE_SIZE];
    uint64_t y_s [SAMPLE_SIZE*Y_PER_X];
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        x_s[i] = distrib(random_generator);
        y_s[i * Y_PER_X] = x_s[i];
        for (int j = 1; j < Y_PER_X; j++) {
            y_s[i * Y_PER_X +j] = distrib(random_generator);
        }
    }

    // Set parameters
    Client client = Client::create(polynomial_modulus, plaintext_modulus,coeff_modulus);
    Server server(client.get_parameters(), client.get_context());

    // Set up encrypted xs for computation 
    Ciphertext x_encrypted_arr [SAMPLE_SIZE];
    for (int i = 0; i < SAMPLE_SIZE; i++) {
        x_encrypted_arr[i] = client.set_x(x_s[i]);
    }

    std::cout << "-------" <<std::endl;
    // Begin test
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < SAMPLE_SIZE; i++) {
        for (int j = 0; j < Y_PER_X; j++) {
            server.compute_z(x_encrypted_arr[i], y_s[i * Y_PER_X + j]);
        }
    }

    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    // End test
    double microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            elapsed).count();
    double time_per_test = microseconds / (double) (SAMPLE_SIZE * Y_PER_X) ;
    std::cout << "Took a total of " << microseconds << " microseconds for " << SAMPLE_SIZE*Y_PER_X << " tests." << std::endl;
    std::cout << "Time per test: " << time_per_test << " microseconds." << std::endl;;
    return time_per_test;
}