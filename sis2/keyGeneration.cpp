// Including the necessary libraries for random number generation and mathematical operations.
#include <iostream>
#include <cmath>
#include <cstdlib>
#include <ctime>

// Using a namespace to prevent potential naming conflicts and to logically group
// associated functionalities.
namespace RSAKeyGeneration {

    /**
    * @class RSAKeyGenerator
    * Represents the key generation process for the RSA algorithm.
    */
    class RSAKeyGenerator {
    private:
        // Private helper function to check if a number is prime.
        bool isPrime(int num) {
            if (num <= 1)
                return false;

            for (int i = 2; i <= sqrt(num); i++) {
                if (num % i == 0)
                    return false;
            }

            return true;
        }

        // Private helper function to generate a random prime number.
        int generateRandomPrime() {
            int randomNum = rand() % 100 + 100; // Generating a random number between 100 and 200
            while (!isPrime(randomNum)) {
                randomNum++;
            }
            return randomNum;
        }

    public:
        /**
        * Generates public and private keys for the RSA algorithm.
        *
        * @param publicKey Reference to store the generated public key.
        * @param privateKey Reference to store the generated private key.
        */
        void generateKeys(int& publicKey, int& privateKey) {
            srand(time(0)); // Seed for random number generation

            // Step 1: Choose two distinct prime numbers p and q
            int p = generateRandomPrime();
            int q = generateRandomPrime();

            // Step 2: Compute n = p * q
            int n = p * q;

            // Step 3: Compute Euler's totient function phi(n)
            int phi = (p - 1) * (q - 1);

            // Step 4: Choose e such that 1 < e < phi(n) and e is coprime to phi(n)
            int e = 2; // Starting from 2
            while (e < phi) {
                if (isPrime(e) && phi % e != 0)
                    break;
                e++;
            }

            // Step 5: Compute d such that (d * e) % phi(n) = 1
            int d = 1;
            while (((d * e) % phi) != 1) {
                d++;
            }

            publicKey = e;
            privateKey = d;
        }
    };
}

int main() {
    int publicKey, privateKey;

    RSAKeyGeneration::RSAKeyGenerator keyGenerator;
    keyGenerator.generateKeys(publicKey, privateKey);

    std::cout << "Public Key (e): " << publicKey << std::endl;
    std::cout << "Private Key (d): " << privateKey << std::endl;

    return 0;
}