//
// Created by Blink on 2018/7/9.
//

#ifndef RAN_EXP_ACTOR_HPP
#define RAN_EXP_ACTOR_HPP

#include "../crypto/crypto.hpp"
class Actor {
public:
    Actor() = delete;
    Actor(std::string &id_, std::string& pubkeyPem) {
        pubKey = Crypto::getPubKey(pubkeyPem);
        ecdhKey = Crypto::ecdh_generate(&ecdhKeyLen, pubKey);
        id = id_;
    }

    EC_KEY* getPubkey() {
        return pubKey;
    }
    unsigned char* getEcdhKey() {
        return ecdhKey;
    }

    int getEcdhKeyLen() {
        return ecdhKeyLen;
    }

    bool setEcdhKey(unsigned char *key, int len) {
        ecdhKey = key;
        ecdhKeyLen = len;
    }

    std::string getId() {
        return id;
    }

    std::string enc(std::string &plain) {
        return std::move(Crypto::encrypt(plain, ecdhKey));
    }

    std::string dec(std::string &cipher) {
        return std::move(Crypto::decrypt(cipher, ecdhKey));
    }

    bool verifySig(std::string &digest, ECDSA_SIG &sig) {
        return Crypto::verifySig(digest, sig, *pubKey);
    }

private:
    EC_KEY *pubKey;
    unsigned char *ecdhKey;
    int ecdhKeyLen;
    std::string id;

};


#endif //RAN_EXP_ACTOR_HPP
