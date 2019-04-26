//
// Created by Blink on 2018/7/6.
//

#ifndef RAN_EXP_CRYPTO_HPP
#define RAN_EXP_CRYPTO_HPP
#include <cryptopp/ida.h>
#include <cryptopp/seed.h>
#include <cryptopp/osrng.h>
#include <cryptopp/basecode.h>
#include <cryptopp/files.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
# include <openssl/crypto.h>
# include <openssl/evp.h>
# include <openssl/bn.h>
#include <vector>
#include <cstring>
#include <sstream>


namespace Crypto {

    extern EC_KEY* privKeyPair;

    void handleErrors(std::string errMsg);

    EC_KEY* getPubKey(std::string pubKeyPem);

    void importPrivKey(std::string privKeyPem);

    void printLeaks();

    ECDSA_SIG* sign(const std::string &digest);

    bool verifySig(const std::string &digest, const ECDSA_SIG &sig, EC_KEY &pubKey);

    unsigned char* ecdh_generate(int *secret_len, EC_KEY* peerKey);

    std::string encrypt(std::string &plain, unsigned char *key);

    std::string decrypt(std::string& cipher, unsigned char *key);


    std::vector<std::string> SecretShareBytes(const std::string& secret, int threshold, int nShares);

    std::string SecretRecoverBytes(std::vector<std::string>& shares, int threshold);


    // Copy from https://stackoverflow.com/questions/5288076/base64-encoding-and-decoding-with-openssl

    extern const char b64_table[65];

    extern const char reverse_table[128];

    std::string base64_encode(const std::string &bindata);

    std::string base64_decode(const std::string &ascdata);
};

#endif //RAN_EXP_CRYPTO_HPP
