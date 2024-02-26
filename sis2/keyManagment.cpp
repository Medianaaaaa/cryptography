// Including the necessary libraries for RSA encryption.
#include <iostream>
#include <string>
#include <cmath>

// Using a namespace to prevent potential naming conflicts and to logically group
// associated functionalities.
namespace KeyManagement {

    /**
    * @class RSAKeyManager
    * Manages RSA keys for encryption and decryption.
    */
    class RSAKeyManager {
    private:
        int publicKey;
        int privateKey;
        int modulus;

        /**
        * Generates a random prime number for key generation.
        *
        * @return int A randomly generated prime number.
        */
        int GeneratePrimeNumber() {
            // This is a simplified version for demonstration purposes.
            // In practice, a more sophisticated algorithm should be used to generate prime numbers.
            return 13; // Example prime number
        }

        /**
        * Calculates the modular exponentiation for RSA encryption and decryption.
        *
        * @param base The base value.
        * @param exponent The exponent value.
        * @param modulus The modulus value.
        * @return int The result of modular exponentiation.
        */
        int ModularExponentiation(int base, int exponent, int modulus) {
            if (modulus == 1)
                return 0;

            int result = 1;
            base = base % modulus;

            while (exponent > 0) {
                if (exponent % 2 == 1)
                    result = (result * base) % modulus;

                exponent = exponent >> 1;
                base = (base * base) % modulus;
            }

            return result;
        }

    public:
        /**
        * Generates RSA public and private keys.
        */
        void GenerateKeys() {
            int p = GeneratePrimeNumber();
            int q = GeneratePrimeNumber();

            modulus = p * q;
            int phi = (p - 1) * (q - 1);

            // Choosing a public key (e) that is coprime with phi.
            publicKey = 7; // Example public key
            // Calculating the corresponding private key (d) using modular inverse.
            privateKey = 103; // Example private key
        }

        /**
        * Encrypts a message using the public key.
        *
        * @param message The message to be encrypted.
        * @return int The encrypted message.
        */
        int EncryptMessage(const std::string& message) {
            int encryptedMessage = 0;

            for (char c : message) {
                encryptedMessage = (encryptedMessage + ModularExponentiation(c, publicKey, modulus)) % modulus;
            }

            return encryptedMessage;
        }

        /**
        * Decrypts an encrypted message using the private key.
        *
        * @param encryptedMessage The message to be decrypted.
        * @return std::string The decrypted message.
        */
        std::string DecryptMessage(int encryptedMessage) {
            std::string decryptedMessage = "";

            int decryptedChar = ModularExponentiation(encryptedMessage, privateKey, modulus);
            decryptedMessage += decryptedChar;

            return decryptedMessage;
        }
    };
}

int main() {
    // Example usage of the RSAKeyManager class
    KeyManagement::RSAKeyManager keyManager;
    keyManager.GenerateKeys();

    std::string originalMessage = "Hello, RSA!";
    int encryptedMessage = keyManager.EncryptMessage(originalMessage);
    std::string decryptedMessage = keyManager.DecryptMessage(encryptedMessage);

    std::cout << "Original Message: " << originalMessage << std::endl;
    std::cout << "Encrypted Message: " << encryptedMessage << std::endl;
    std::cout << "Decrypted Message: " << decryptedMessage << std::endl;

    return 0;
}