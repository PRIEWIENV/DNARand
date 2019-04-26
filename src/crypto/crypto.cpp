//
// Created by Blink on 2018/7/6.
//

#include "crypto.hpp"
#include <cstdio>
#include <cstring>
#include <stdio.h>
#include <assert.h>

namespace Crypto {
    EC_KEY* privKeyPair;

    void handleErrors(std::string errMsg) {
        perror(errMsg.c_str());
        exit(0);
    }

    EC_KEY* getPubKey(std::string pubKeyPem) {
        //std::cout <<"[DEBUG] pubKeyPem: " <<  pubKeyPem << std::endl;
        EC_KEY* ecpubkey;
        BIO *bio = BIO_new_mem_buf(pubKeyPem.c_str(), pubKeyPem.length());
        ecpubkey = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
        if (NULL == ecpubkey) {
            throw std::invalid_argument("Invalid public EC Key");
        }
        EC_KEY_print_fp(stdout, ecpubkey, 0);
        /*
        const EC_POINT *ecpoint = EC_KEY_get0_public_key(ecpubkey);
        EC_KEY_print_fp(stdout, ecpubkey, 0);

        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();

        EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (EC_POINT_get_affine_coordinates_GFp(ec_group, ecpoint, x, y, NULL)) {
            BN_print_fp(stdout, x);
            putc('\n', stdout);
            BN_print_fp(stdout, y);
            putc('\n', stdout);
        }
         */
        return ecpubkey;
    }

    void printLeaks() {
        BIO *b;
        b=BIO_new_file("leak.log","w");
        CRYPTO_mem_leaks(b);
        BIO_free(b);

    }
    void importPrivKey(std::string privKeyPem) {
        BIO *bio = BIO_new_mem_buf(privKeyPem.c_str(), privKeyPem.length());
        privKeyPair = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
        if (NULL == privKeyPair) {
            throw std::invalid_argument("Invalid public EC Key");
        }
        EC_KEY_print_fp(stdout, privKeyPair, 0);
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    }

    ECDSA_SIG* sign(const std::string &digest) {
        unsigned char* digest_uchars = reinterpret_cast<unsigned char*>(const_cast<char*>(digest.c_str()));
        ECDSA_SIG* sig = ECDSA_do_sign(digest_uchars, digest.length(), privKeyPair);// 签名
        return sig;
    }

    bool verifySig(const std::string &digest, const ECDSA_SIG &sig, EC_KEY &pubKey) {
        unsigned char* digest_uchars = reinterpret_cast<unsigned char*>(const_cast<char*>(digest.c_str()));
        int ret = ECDSA_do_verify(digest_uchars, digest.length(), &sig, &pubKey);
        if (ret == 0)
            return false;
        return true;
    }

    unsigned char* ecdh_generate(int *secret_len, EC_KEY* peerKey) {
        EC_KEY *key;
        int field_size;
        unsigned char *secret;

        key = privKeyPair;

        field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
        *secret_len = (field_size + 7) / 8;

        if ((secret = static_cast<unsigned char *>(OPENSSL_malloc(*secret_len))) == NULL) {
            handleErrors("Error to alloc memory while generating ECDH Key");
        }

        *secret_len = ECDH_compute_key(secret, *secret_len, EC_KEY_get0_public_key(peerKey), key, NULL);

        return secret;
    }

    std::string encrypt(std::string &plain, unsigned char *key) {
        unsigned char* plain_uchars = reinterpret_cast<unsigned char*>(const_cast<char*>(plain.c_str()));
        int plain_len = plain.length();
        EVP_CIPHER_CTX *ctx;
        if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors("Error while encrypting");

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL))
            handleErrors("Error while encrypting");

        static unsigned char cipher_uchars[2048];
        //unsigned char* cipher_uchars = new unsigned char[2048];
        int temp_len;
        int cipher_len;

        if (1 != EVP_EncryptUpdate(ctx, cipher_uchars, &temp_len, plain_uchars, plain_len))
            handleErrors("Error while encrypting");
        cipher_len = temp_len;

        if (1 != EVP_EncryptFinal_ex(ctx, cipher_uchars + temp_len, &temp_len))
            handleErrors("Error while encrypting");
        cipher_len += temp_len;
        EVP_CIPHER_CTX_free(ctx);
        std::string result = std::string(cipher_uchars, cipher_uchars + cipher_len);
        //delete[] cipher_uchars;
        return std::move(result);
    }

    std::string decrypt(std::string& cipher, unsigned char *key) {

        //unsigned char* cipher_uchars = reinterpret_cast<unsigned char*>(const_cast<char*>(cipher.c_str()));
        int cipher_len = cipher.length();
        unsigned char* cipher_uchars = new unsigned char[cipher_len + 1];
        memcpy(cipher_uchars, cipher.c_str(), cipher_len);
        cipher_uchars[cipher_len] = 0;
        EVP_CIPHER_CTX *ctx;

        if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors("Error while decrypting");


        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL))
            handleErrors("Error while decrypting");

        unsigned char* plain_uchars = new unsigned char[2048];
        int temp_len;
        int plain_len;
        //EVP_CIPHER_CTX_set_padding(ctx, 0);
        if (1 != EVP_DecryptUpdate(ctx, plain_uchars, &temp_len, cipher_uchars, cipher_len))
            handleErrors("Error while decrypting");
        plain_len = temp_len;

        if (1 != EVP_DecryptFinal_ex(ctx, plain_uchars + temp_len, &temp_len))
            handleErrors("Error while decrypting");
        plain_len += temp_len;

        EVP_CIPHER_CTX_free(ctx);
        std::string result = std::string(plain_uchars, plain_uchars + plain_len);
        delete[] plain_uchars;
        delete[] cipher_uchars;
        return std::move(result);
    }

    std::vector<std::string> SecretShareBytes(const std::string& secret, int threshold, int nShares) {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::ChannelSwitch *channelSwitch;
        CryptoPP::ArraySource source(secret, false, new CryptoPP::SecretSharing( rng, threshold, nShares, channelSwitch = new CryptoPP::ChannelSwitch));

        std::vector<std::ostringstream> shares(nShares);
        CryptoPP::vector_member_ptrs<CryptoPP::FileSink> sinks(nShares);
        std::string channel;
        for (int i = 0; i < nShares; i++) {
            sinks[i].reset(new CryptoPP::FileSink(shares[i]));

            channel = CryptoPP::WordToString<CryptoPP::word32> (i);
            sinks[i]->Put((CryptoPP::byte *)channel.data(), 4);
            channelSwitch->AddRoute(channel, *sinks[i], CryptoPP::DEFAULT_CHANNEL);
        }
        source.PumpAll();

        std::vector<std::string> res;

        for (const auto& share : shares) {
            res.push_back(std::string(share.str()));
        }
        return std::move(res);
    }

    std::string SecretRecoverBytes(std::vector<std::string>& shares, int threshold) {
        std::ostringstream out;
        CryptoPP::SecretRecovery recovery(threshold, new CryptoPP::FileSink(out));
        CryptoPP::SecByteBlock channel(4);

        for (int i = 0; i < threshold; i++) {
            CryptoPP::ArraySource arraySource(shares[i], false);

            arraySource.Pump(4);
            arraySource.Get(channel, 4);
            arraySource.Attach(new CryptoPP::ChannelSwitch(recovery, std::string((char*)channel.begin(), 4)));

            arraySource.PumpAll();
        }

        return std::string(out.str());
    }

    const char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    const char reverse_table[128] = {
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
            64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
            64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
            64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
    };
    std::string base64_encode(const std::string &bindata) {
        using std::string;
        using std::numeric_limits;

        if (bindata.size() > (numeric_limits<string::size_type>::max() / 4u) * 3u) {
            throw std::length_error("Converting too large a string to base64.");
        }

        const std::size_t binlen = bindata.size();
        // Use = signs so the end is properly padded.
        string retval((((binlen + 2) / 3) * 4), '=');
        std::size_t outpos = 0;
        int bits_collected = 0;
        unsigned int accumulator = 0;
        const string::const_iterator binend = bindata.end();

        for (string::const_iterator i = bindata.begin(); i != binend; ++i) {
            accumulator = (accumulator << 8) | (*i & 0xffu);
            bits_collected += 8;
            while (bits_collected >= 6) {
                bits_collected -= 6;
                retval[outpos++] = b64_table[(accumulator >> bits_collected) & 0x3fu];
            }
        }
        if (bits_collected > 0) { // Any trailing bits that are missing.
            assert(bits_collected < 6);
            accumulator <<= 6 - bits_collected;
            retval[outpos++] = b64_table[accumulator & 0x3fu];
        }
        assert(outpos >= (retval.size() - 2));
        assert(outpos <= retval.size());
        return retval;
    }

    std::string base64_decode(const std::string &ascdata) {
        using std::string;
        string retval;
        const string::const_iterator last = ascdata.end();
        int bits_collected = 0;
        unsigned int accumulator = 0;
        for (string::const_iterator i = ascdata.begin(); i != last; ++i) {
            const int c = *i;
            if (std::isspace(c) || c == '=') {
                // Skip whitespace and padding. Be liberal in what you accept.
                continue;
            }
            if ((c > 127) || (c < 0) || (reverse_table[c] > 63)) {
                throw std::invalid_argument("This contains characters not legal in a base64 encoded string.");
            }
            accumulator = (accumulator << 6) | reverse_table[c];
            bits_collected += 6;
            if (bits_collected >= 8) {
                bits_collected -= 8;
                retval += static_cast<char>((accumulator >> bits_collected) & 0xffu);
            }
        }
        return retval;
    }
}