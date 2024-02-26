#include <iostream>
#include <cmath>

namespace RSAEncryption {

    /**
    * @class RSA
    * Represents the RSA encryption and decryption algorithm.
    */
    class RSA {
    private:
        long long p; // First prime number
        long long q; // Second prime number
        long long n; // Modulus
        long long phi; // Euler's totient function value
        long long e; // Public key exponent
        long long d; // Private key exponent

        /**
        * Computes the Greatest Common Divisor (GCD) of two numbers using Euclidean algorithm.
        *
        * @param a The first number.
        * @param b The second number.
        * @return long long The GCD of a and b.
        */
        long long GCD(long long a, long long b) {
            if (b == 0)
                return a;

            return GCD(b, a % b);
        }

        /**
        * Computes the modular inverse of a number using Extended Euclidean algorithm.
        *
        * @param a The number for which the modular inverse is to be found.
        * @param m The modulus.
        * @return long long The modular inverse of a modulo m.
        */
        long long ModInverse(long long a, long long m) {
            long long m0 = m;
            long long y = 0, x = 1;

            if (m == 1)
                return 0;

            while (a > 1) {
                long long q = a / m;
                long long t = m;

                m = a % m;
                a = t;
                t = y;

                y = x - q * y;
                x = t;
            }

            if (x < 0)
                x += m0;

            return x;
        }

    public:
        /**
        * Constructs an RSA object with the provided prime numbers.
        *
        * @param prime1 The first prime number.
        * @param prime2 The second prime number.
        */
        RSA(long long prime1, long long prime2) {
            p = prime1;
            q = prime2;
            n = p * q;
            phi = (p - 1) * (q - 1);

            // Choosing e such that 1 < e < phi and e is coprime with phi
            for (e = 2; e < phi; e++) {
                if (GCD(e, phi) == 1)
                    break;
            }

            // Calculating d, the modular multiplicative inverse of e modulo phi
            d = ModInverse(e, phi);
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
        * @param encryptedMessage The message to be decrypted.
        * @return long long The decrypted message.
        */
        long long Decrypt(long long encryptedMessage) {
            return std::pow(encryptedMessage, d) % n;
        }
    };
}

int main() {
    RSAEncryption::RSA rsa(61, 53); // Using prime numbers 61 and 53 for RSA encryption

    long long originalMessage = 1234;
    long long encryptedMessage = rsa.Encrypt(originalMessage);
    long long decryptedMessage = rsa.Decrypt(encryptedMessage);

    std::cout << "Original Message: " << originalMessage << std::endl;
    std::cout << "Encrypted Message: " << encryptedMessage << std::endl;
    std::cout << "Decrypted Message: " << decryptedMessage << std::endl;

    return 0;
}