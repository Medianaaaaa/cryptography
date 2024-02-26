// Including the necessary libraries for RSA encryption.
#include <iostream>
#include <cmath>



// Using a namespace to prevent potential naming conflicts and to logically group
// associated functionalities.
namespace RSAEncryption {

    /**
    * @class RSA
    * Represents the RSA encryption algorithm implementation.
    */
    class RSA {
    private:
        // Private key components.
        long long p; // First prime number
        long long q; // Second prime number
        long long n; // Modulus for both the public and private keys
        long long phi; // Euler's totient function value
        long long e; // Public exponent
        long long d; // Private exponent

        /**
        * Computes the Greatest Common Divisor (GCD) of two integers using a recursive algorithm.
        *
        * @param a The first integer.
        * @param b The second integer, which will be reduced on each recursive call.
        * @return long long The GCD of a and b.
        */
        long long GCD(long long a, long long b) {
            if (b == 0)
                return a;

            return GCD(b, a % b);
        }

        /**
        * Generates the public and private keys for RSA encryption.
        */
        void GenerateKeys() {
            n = p * q;
            phi = (p - 1) * (q - 1);

            // Choosing a public exponent 'e' such that 1 < e < phi and GCD(e, phi) = 1
            for (e = 2; e < phi; e++) {
                if (GCD(e, phi) == 1)
                    break;
            }

            // Calculating the private exponent 'd' using modular inverse
            for (d = 2; d < phi; d++) {
                if ((e * d) % phi == 1)
                    break;
            }
        }

    public:
        /**
        * Constructs an RSA object with the provided prime numbers for key generation.
        *
        * @param prime1 The first prime number.
        * @param prime2 The second prime number.
        */
        RSA(long long prime1, long long prime2) : p(prime1), q(prime2) {
            GenerateKeys();
        }

        /**
        * Encrypts a message using the RSA algorithm.
        *
        * @param message The message to be encrypted.
        * @return long long The encrypted message.
        */
        long long Encrypt(long long message) {
            return std::pow(message, e) % n;
        }

        /**
        * Decrypts an encrypted message using the RSA algorithm.
        *
        * @param encryptedMessage The encrypted message to be decrypted.
        * @return long long The decrypted message.
        */
        long long Decrypt(long long encryptedMessage) {
            return std::pow(encryptedMessage, d) % n;
        }
    };
}

int main() {
    // Example of using RSA encryption
    {
        RSAEncryption::RSA rsa(61, 53); // Choosing prime numbers 61 and 53 for key generation
        long long originalMessage = 1234;
        long long encryptedMessage = rsa.Encrypt(originalMessage);
        long long decryptedMessage = rsa.Decrypt(encryptedMessage);

        std::cout << "Original Message: " << originalMessage << std::endl;
        std::cout << "Encrypted Message: " << encryptedMessage << std::endl;
        std::cout << "Decrypted Message: " << decryptedMessage << std::endl;
    }

    return 0;
}