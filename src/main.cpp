#include <stdio.h>
#include <iostream>
#include <vector>
#include <random>
#include "client.h"
#include "test_bench.h"
#include "server.h"
#include "seal/seal.h"

using namespace seal;

int main(int argc, char *argv[]){
    if (argc == 2 && argv[1][0] == '0') {
        // Demo
        Client client = Client::create(4096, 1024);
        Server server(client.get_parameters(), client.get_context());
        

        std::mt19937 random_generator(1);
        std::uniform_int_distribution<> distrib(0, 1023);
        uint64_t x;
        uint64_t y_s [3];
        x = distrib(random_generator);
        y_s[0] = x;
        for (int j = 1; j < 3; j++) {
            y_s[j] = distrib(random_generator);
        }

        Ciphertext x_encrypted;
        Ciphertext z_encrypted;
        uint64_t y;
        x_encrypted = client.set_x(x);
        std::cout << "x: " << x << std::endl;
        for (int i = 0; i < 3 ; i++) {
            y = y_s[i];
            z_encrypted = server.compute_z(x_encrypted, y);
            std::cout << "y: " << y << "\t|| is_equal: " << client.is_zero(z_encrypted) << std::endl; 
        }
        return 0;
    }

    std::string result = "";
    std::vector<size_t> poly_mods = {1024,2048,4096,8192,16384,32768};
    std::vector<size_t> plain_mods = {1024,2048,4096,8192,16384,32768};
    std::vector<std::pair<std::string, double (*) (size_t, size_t, std::vector<Modulus>)>> tests = {
        {"Overall timing test", overall_timing_test},
        {"Encryption timing test", encryption_timing_test},
        {"Computation timing test", computation_timing_test},
        {"Decryption timing test", decryption_timing_test}
    };

    for (auto test : tests) {
        result += "=== " + test.first + " === \n ";
        std::cout <<  "=== " + test.first + " === \n "<< std::endl;
        for (auto poly_mod : poly_mods) {
            for (auto plain_mod : plain_mods) {
                std::vector<Modulus> coeff_mod = CoeffModulus::BFVDefault(poly_mod); 
                double time_per_test = test.second(poly_mod, plain_mod, coeff_mod);
                std::stringstream ss;
                ss << "poly_mod = " << poly_mod << " \t|| plain_mod = " << plain_mod << std::endl;
                ss << time_per_test << " microseconds per test" << std::endl;
                result += ss.str();
            }
        }
    }
    

    result += "=== Noise test === \n ";
    for (auto poly_mod : poly_mods) {
        for (auto plain_mod : plain_mods) {
            std::vector<Modulus> coeff_mod = CoeffModulus::BFVDefault(poly_mod); 
            std::vector<int> noise_test_result = overall_noise_test(poly_mod,plain_mod, coeff_mod);
            std::stringstream ss;
            ss << "poly_mod = " << poly_mod << " \t|| plain_mod = " << plain_mod << std::endl;
            ss << "Fresh encryption: "<< noise_test_result[0] <<" bits\t|| After computation: " <<noise_test_result[1] <<" bits."<< std::endl;
            result += ss.str();
        }
    }


    std::cout << "======\n" << result << std::endl;
    return 0;
}

// We find that encryption generally takes the most time, and time taken for computations
// generally grows at a rate of poly_mod^2. Noise budget increases approximately linearly
// wrt poly_mod (and hence coeff_mod) and decreases as plaintext_mod increases.
// Computation of z does not consume any noise as expected.
// Results: 
// poly_mod = 1024 	|| plain_mod = 1024:	149 microseconds per test
// poly_mod = 1024 	|| plain_mod = 2048:	143 microseconds per test
// poly_mod = 1024 	|| plain_mod = 4096:	143 microseconds per test
// poly_mod = 1024 	|| plain_mod = 8192:	175 microseconds per test
// poly_mod = 1024 	|| plain_mod = 16384:	176 microseconds per test
// poly_mod = 1024 	|| plain_mod = 32768:	144 microseconds per test
// poly_mod = 2048 	|| plain_mod = 1024:	281 microseconds per test
// poly_mod = 2048 	|| plain_mod = 2048:	273 microseconds per test
// poly_mod = 2048 	|| plain_mod = 4096:	273 microseconds per test
// poly_mod = 2048 	|| plain_mod = 8192:	272 microseconds per test
// poly_mod = 2048 	|| plain_mod = 16384:	282 microseconds per test
// poly_mod = 2048 	|| plain_mod = 32768:	273 microseconds per test
// poly_mod = 4096 	|| plain_mod = 1024:	968 microseconds per test
// poly_mod = 4096 	|| plain_mod = 2048:	887 microseconds per test
// poly_mod = 4096 	|| plain_mod = 4096:	1002 microseconds per test
// poly_mod = 4096 	|| plain_mod = 8192:	939 microseconds per test
// poly_mod = 4096 	|| plain_mod = 16384:	914 microseconds per test
// poly_mod = 4096 	|| plain_mod = 32768:	929 microseconds per test
// poly_mod = 8192 	|| plain_mod = 1024:	2716 microseconds per test
// poly_mod = 8192 	|| plain_mod = 2048:	2812 microseconds per test
// poly_mod = 8192 	|| plain_mod = 4096:	2561 microseconds per test
// poly_mod = 8192 	|| plain_mod = 8192:	2514 microseconds per test
// poly_mod = 8192 	|| plain_mod = 16384:	2563 microseconds per test
// poly_mod = 8192 	|| plain_mod = 32768:	2593 microseconds per test
// poly_mod = 16384 	|| plain_mod = 1024:	9196 microseconds per test
// poly_mod = 16384 	|| plain_mod = 2048:	9544 microseconds per test
// poly_mod = 16384 	|| plain_mod = 4096:	9774 microseconds per test
// poly_mod = 16384 	|| plain_mod = 8192:	9624 microseconds per test
// poly_mod = 16384 	|| plain_mod = 16384:	9950 microseconds per test
// poly_mod = 16384 	|| plain_mod = 32768:	10074 microseconds per test
// poly_mod = 32768 	|| plain_mod = 1024:	38032 microseconds per test
// poly_mod = 32768 	|| plain_mod = 2048:	37331 microseconds per test
// poly_mod = 32768 	|| plain_mod = 4096:	36122 microseconds per test
// poly_mod = 32768 	|| plain_mod = 8192:	42014 microseconds per test
// poly_mod = 32768 	|| plain_mod = 16384:	37837 microseconds per test
// poly_mod = 32768 	|| plain_mod = 32768:	37342 microseconds per test
// === Encryption timing test === 
//  poly_mod = 1024 	|| plain_mod = 1024:	117 microseconds per test
// poly_mod = 1024 	|| plain_mod = 2048:	114 microseconds per test
// poly_mod = 1024 	|| plain_mod = 4096:	111 microseconds per test
// poly_mod = 1024 	|| plain_mod = 8192:	112 microseconds per test
// poly_mod = 1024 	|| plain_mod = 16384:	111 microseconds per test
// poly_mod = 1024 	|| plain_mod = 32768:	115 microseconds per test
// poly_mod = 2048 	|| plain_mod = 1024:	214 microseconds per test
// poly_mod = 2048 	|| plain_mod = 2048:	212 microseconds per test
// poly_mod = 2048 	|| plain_mod = 4096:	208 microseconds per test
// poly_mod = 2048 	|| plain_mod = 8192:	209 microseconds per test
// poly_mod = 2048 	|| plain_mod = 16384:	228 microseconds per test
// poly_mod = 2048 	|| plain_mod = 32768:	220 microseconds per test
// poly_mod = 4096 	|| plain_mod = 1024:	725 microseconds per test
// poly_mod = 4096 	|| plain_mod = 2048:	707 microseconds per test
// poly_mod = 4096 	|| plain_mod = 4096:	666 microseconds per test
// poly_mod = 4096 	|| plain_mod = 8192:	696 microseconds per test
// poly_mod = 4096 	|| plain_mod = 16384:	683 microseconds per test
// poly_mod = 4096 	|| plain_mod = 32768:	658 microseconds per test
// poly_mod = 8192 	|| plain_mod = 1024:	1823 microseconds per test
// poly_mod = 8192 	|| plain_mod = 2048:	1873 microseconds per test
// poly_mod = 8192 	|| plain_mod = 4096:	1856 microseconds per test
// poly_mod = 8192 	|| plain_mod = 8192:	1900 microseconds per test
// poly_mod = 8192 	|| plain_mod = 16384:	1883 microseconds per test
// poly_mod = 8192 	|| plain_mod = 32768:	1925 microseconds per test
// poly_mod = 16384 	|| plain_mod = 1024:	6733 microseconds per test
// poly_mod = 16384 	|| plain_mod = 2048:	6238 microseconds per test
// poly_mod = 16384 	|| plain_mod = 4096:	6514 microseconds per test
// poly_mod = 16384 	|| plain_mod = 8192:	6758 microseconds per test
// poly_mod = 16384 	|| plain_mod = 16384:	6890 microseconds per test
// poly_mod = 16384 	|| plain_mod = 32768:	6426 microseconds per test
// poly_mod = 32768 	|| plain_mod = 1024:	30709 microseconds per test
// poly_mod = 32768 	|| plain_mod = 2048:	25436 microseconds per test
// poly_mod = 32768 	|| plain_mod = 4096:	25674 microseconds per test
// poly_mod = 32768 	|| plain_mod = 8192:	24887 microseconds per test
// poly_mod = 32768 	|| plain_mod = 16384:	25363 microseconds per test
// poly_mod = 32768 	|| plain_mod = 32768:	24053 microseconds per test
// === Computation timing test === 
//  poly_mod = 1024 	|| plain_mod = 1024:	1 microseconds per test
// poly_mod = 1024 	|| plain_mod = 2048:	1 microseconds per test
// poly_mod = 1024 	|| plain_mod = 4096:	0 microseconds per test
// poly_mod = 1024 	|| plain_mod = 8192:	1 microseconds per test
// poly_mod = 1024 	|| plain_mod = 16384:	0 microseconds per test
// poly_mod = 1024 	|| plain_mod = 32768:	1 microseconds per test
// poly_mod = 2048 	|| plain_mod = 1024:	1 microseconds per test
// poly_mod = 2048 	|| plain_mod = 2048:	1 microseconds per test
// poly_mod = 2048 	|| plain_mod = 4096:	1 microseconds per test
// poly_mod = 2048 	|| plain_mod = 8192:	1 microseconds per test
// poly_mod = 2048 	|| plain_mod = 16384:	1 microseconds per test
// poly_mod = 2048 	|| plain_mod = 32768:	1 microseconds per test
// poly_mod = 4096 	|| plain_mod = 1024:	9 microseconds per test
// poly_mod = 4096 	|| plain_mod = 2048:	5 microseconds per test
// poly_mod = 4096 	|| plain_mod = 4096:	4 microseconds per test
// poly_mod = 4096 	|| plain_mod = 8192:	4 microseconds per test
// poly_mod = 4096 	|| plain_mod = 16384:	4 microseconds per test
// poly_mod = 4096 	|| plain_mod = 32768:	4 microseconds per test
// poly_mod = 8192 	|| plain_mod = 1024:	38 microseconds per test
// poly_mod = 8192 	|| plain_mod = 2048:	32 microseconds per test
// poly_mod = 8192 	|| plain_mod = 4096:	34 microseconds per test
// poly_mod = 8192 	|| plain_mod = 8192:	25 microseconds per test
// poly_mod = 8192 	|| plain_mod = 16384:	38 microseconds per test
// poly_mod = 8192 	|| plain_mod = 32768:	25 microseconds per test
// poly_mod = 16384 	|| plain_mod = 1024:	99 microseconds per test
// poly_mod = 16384 	|| plain_mod = 2048:	109 microseconds per test
// poly_mod = 16384 	|| plain_mod = 4096:	141 microseconds per test
// poly_mod = 16384 	|| plain_mod = 8192:	115 microseconds per test
// poly_mod = 16384 	|| plain_mod = 16384:	97 microseconds per test
// poly_mod = 16384 	|| plain_mod = 32768:	102 microseconds per test
// poly_mod = 32768 	|| plain_mod = 1024:	460 microseconds per test
// poly_mod = 32768 	|| plain_mod = 2048:	583 microseconds per test
// poly_mod = 32768 	|| plain_mod = 4096:	487 microseconds per test
// poly_mod = 32768 	|| plain_mod = 8192:	491 microseconds per test
// poly_mod = 32768 	|| plain_mod = 16384:	532 microseconds per test
// poly_mod = 32768 	|| plain_mod = 32768:	520 microseconds per test
// === Decryption timing test === 
//  poly_mod = 1024 	|| plain_mod = 1024:	37 microseconds per test
// poly_mod = 1024 	|| plain_mod = 2048:	31 microseconds per test
// poly_mod = 1024 	|| plain_mod = 4096:	31 microseconds per test
// poly_mod = 1024 	|| plain_mod = 8192:	30 microseconds per test
// poly_mod = 1024 	|| plain_mod = 16384:	30 microseconds per test
// poly_mod = 1024 	|| plain_mod = 32768:	30 microseconds per test
// poly_mod = 2048 	|| plain_mod = 1024:	62 microseconds per test
// poly_mod = 2048 	|| plain_mod = 2048:	63 microseconds per test
// poly_mod = 2048 	|| plain_mod = 4096:	64 microseconds per test
// poly_mod = 2048 	|| plain_mod = 8192:	60 microseconds per test
// poly_mod = 2048 	|| plain_mod = 16384:	61 microseconds per test
// poly_mod = 2048 	|| plain_mod = 32768:	60 microseconds per test
// poly_mod = 4096 	|| plain_mod = 1024:	207 microseconds per test
// poly_mod = 4096 	|| plain_mod = 2048:	199 microseconds per test
// poly_mod = 4096 	|| plain_mod = 4096:	201 microseconds per test
// poly_mod = 4096 	|| plain_mod = 8192:	195 microseconds per test
// poly_mod = 4096 	|| plain_mod = 16384:	195 microseconds per test
// poly_mod = 4096 	|| plain_mod = 32768:	193 microseconds per test
// poly_mod = 8192 	|| plain_mod = 1024:	703 microseconds per test
// poly_mod = 8192 	|| plain_mod = 2048:	680 microseconds per test
// poly_mod = 8192 	|| plain_mod = 4096:	667 microseconds per test
// poly_mod = 8192 	|| plain_mod = 8192:	723 microseconds per test
// poly_mod = 8192 	|| plain_mod = 16384:	921 microseconds per test
// poly_mod = 8192 	|| plain_mod = 32768:	696 microseconds per test
// poly_mod = 16384 	|| plain_mod = 1024:	3095 microseconds per test
// poly_mod = 16384 	|| plain_mod = 2048:	2988 microseconds per test
// poly_mod = 16384 	|| plain_mod = 4096:	3043 microseconds per test
// poly_mod = 16384 	|| plain_mod = 8192:	2937 microseconds per test
// poly_mod = 16384 	|| plain_mod = 16384:	3931 microseconds per test
// poly_mod = 16384 	|| plain_mod = 32768:	3114 microseconds per test
// poly_mod = 32768 	|| plain_mod = 1024:	12515 microseconds per test
// poly_mod = 32768 	|| plain_mod = 2048:	12639 microseconds per test
// poly_mod = 32768 	|| plain_mod = 4096:	14221 microseconds per test
// poly_mod = 32768 	|| plain_mod = 8192:	12169 microseconds per test
// poly_mod = 32768 	|| plain_mod = 16384:	11703 microseconds per test
// poly_mod = 32768 	|| plain_mod = 32768:	11652 microseconds per test
// === Noise test === 
//  poly_mod = 1024 	|| plain_mod = 1024
// Fresh encryption: 7 bits	|| After computation: 7 bits.
// poly_mod = 1024 	|| plain_mod = 2048
// Fresh encryption: 6 bits	|| After computation: 6 bits.
// poly_mod = 1024 	|| plain_mod = 4096
// Fresh encryption: 5 bits	|| After computation: 5 bits.
// poly_mod = 1024 	|| plain_mod = 8192
// Fresh encryption: 4 bits	|| After computation: 4 bits.
// poly_mod = 1024 	|| plain_mod = 16384
// Fresh encryption: 3 bits	|| After computation: 3 bits.
// poly_mod = 1024 	|| plain_mod = 32768
// Fresh encryption: 2 bits	|| After computation: 2 bits.
// poly_mod = 2048 	|| plain_mod = 1024
// Fresh encryption: 33 bits	|| After computation: 33 bits.
// poly_mod = 2048 	|| plain_mod = 2048
// Fresh encryption: 32 bits	|| After computation: 32 bits.
// poly_mod = 2048 	|| plain_mod = 4096
// Fresh encryption: 31 bits	|| After computation: 31 bits.
// poly_mod = 2048 	|| plain_mod = 8192
// Fresh encryption: 30 bits	|| After computation: 30 bits.
// poly_mod = 2048 	|| plain_mod = 16384
// Fresh encryption: 29 bits	|| After computation: 29 bits.
// poly_mod = 2048 	|| plain_mod = 32768
// Fresh encryption: 28 bits	|| After computation: 28 bits.
// poly_mod = 4096 	|| plain_mod = 1024
// Fresh encryption: 55 bits	|| After computation: 55 bits.
// poly_mod = 4096 	|| plain_mod = 2048
// Fresh encryption: 54 bits	|| After computation: 54 bits.
// poly_mod = 4096 	|| plain_mod = 4096
// Fresh encryption: 53 bits	|| After computation: 53 bits.
// poly_mod = 4096 	|| plain_mod = 8192
// Fresh encryption: 52 bits	|| After computation: 52 bits.
// poly_mod = 4096 	|| plain_mod = 16384
// Fresh encryption: 51 bits	|| After computation: 51 bits.
// poly_mod = 4096 	|| plain_mod = 32768
// Fresh encryption: 50 bits	|| After computation: 50 bits.
// poly_mod = 8192 	|| plain_mod = 1024
// Fresh encryption: 156 bits	|| After computation: 156 bits.
// poly_mod = 8192 	|| plain_mod = 2048
// Fresh encryption: 155 bits	|| After computation: 155 bits.
// poly_mod = 8192 	|| plain_mod = 4096
// Fresh encryption: 154 bits	|| After computation: 154 bits.
// poly_mod = 8192 	|| plain_mod = 8192
// Fresh encryption: 153 bits	|| After computation: 153 bits.
// poly_mod = 8192 	|| plain_mod = 16384
// Fresh encryption: 152 bits	|| After computation: 152 bits.
// poly_mod = 8192 	|| plain_mod = 32768
// Fresh encryption: 151 bits	|| After computation: 151 bits.
// poly_mod = 16384 	|| plain_mod = 1024
// Fresh encryption: 371 bits	|| After computation: 371 bits.
// poly_mod = 16384 	|| plain_mod = 2048
// Fresh encryption: 370 bits	|| After computation: 370 bits.
// poly_mod = 16384 	|| plain_mod = 4096
// Fresh encryption: 369 bits	|| After computation: 369 bits.
// poly_mod = 16384 	|| plain_mod = 8192
// Fresh encryption: 368 bits	|| After computation: 368 bits.
// poly_mod = 16384 	|| plain_mod = 16384
// Fresh encryption: 367 bits	|| After computation: 367 bits.
// poly_mod = 16384 	|| plain_mod = 32768
// Fresh encryption: 366 bits	|| After computation: 366 bits.
// poly_mod = 32768 	|| plain_mod = 1024
// Fresh encryption: 806 bits	|| After computation: 806 bits.
// poly_mod = 32768 	|| plain_mod = 2048
// Fresh encryption: 805 bits	|| After computation: 805 bits.
// poly_mod = 32768 	|| plain_mod = 4096
// Fresh encryption: 804 bits	|| After computation: 804 bits.
// poly_mod = 32768 	|| plain_mod = 8192
// Fresh encryption: 803 bits	|| After computation: 803 bits.
// poly_mod = 32768 	|| plain_mod = 16384
// Fresh encryption: 802 bits	|| After computation: 802 bits.
// poly_mod = 32768 	|| plain_mod = 32768
// Fresh encryption: 801 bits	|| After computation: 801 bits.
// Default bit length of coeff mod for each poly_mod:
// 1024 -> 27 
// 2048 -> 54
// 4096 -> 109
// 8192 -> 218
// 16384 -> 438
// 32768 -> 881