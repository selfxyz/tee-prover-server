pragma circom 2.1.9;

include "../crypto/signature/rsapss/rsapss3.circom";
include "../crypto/signature/rsapss/rsapss65537.circom";
include "../crypto/signature/ecdsa/ecdsaVerifier.circom";
include "../crypto/signature/rsa/verifyRsa3Pkcs1v1_5.circom";
include "../crypto/signature/rsa/verifyRsa65537Pkcs1v1_5.circom";
include "@openpassport/zk-email-circuits/utils/bytes.circom";

template SignatureVerifier(signatureAlgorithm, n, k) {
    var kLengthFactor = getKLengthFactor(signatureAlgorithm);
    var kScaled = k * kLengthFactor;

    var HASH_LEN_BITS = getHashLength(signatureAlgorithm);

    signal input hash[HASH_LEN_BITS];
    signal input pubKey[kScaled];
    signal input signature[kScaled];


    var msg_len = (HASH_LEN_BITS + n) \ n;

    signal hashParsed[msg_len] <== HashParser(signatureAlgorithm, n, k)(hash);
   
    if (
        signatureAlgorithm == 1
        || signatureAlgorithm == 3
        || signatureAlgorithm == 10
        || signatureAlgorithm == 11
        || signatureAlgorithm == 14
        || signatureAlgorithm == 15
        || signatureAlgorithm == 31
    ) { 
        component rsa65537 = VerifyRsa65537Pkcs1v1_5(n, k, HASH_LEN_BITS);
        for (var i = 0; i < msg_len; i++) {
            rsa65537.message[i] <== hashParsed[i];
        }
        for (var i = msg_len; i < k; i++) {
            rsa65537.message[i] <== 0;
        }
        rsa65537.modulus <== pubKey;
        rsa65537.signature <== signature;

    }
    if (
        signatureAlgorithm == 13
        || signatureAlgorithm == 32
    ) {
        component rsa3 = VerifyRsa3Pkcs1v1_5(n, k, HASH_LEN_BITS);
        for (var i = 0; i < msg_len; i++) {
            rsa3.message[i] <== hashParsed[i];
        }
        for (var i = msg_len; i < k; i++) {
            rsa3.message[i] <== 0;
        }
        rsa3.modulus <== pubKey;
        rsa3.signature <== signature;
    }
    if (
        signatureAlgorithm == 4 
        || signatureAlgorithm == 12
        || signatureAlgorithm == 18
        || signatureAlgorithm == 19
    ) {
        var pubKeyBitsLength = getKeyLength(signatureAlgorithm);
        var SALT_LEN = HASH_LEN_BITS / 8;
        var E_BITS = getExponentBits(signatureAlgorithm);
        component rsaPss65537ShaVerification = VerifyRsaPss65537Sig(n, k, SALT_LEN, HASH_LEN_BITS, pubKeyBitsLength);
        rsaPss65537ShaVerification.pubkey <== pubKey;
        rsaPss65537ShaVerification.signature <== signature;
        rsaPss65537ShaVerification.hashed <== hash; // send the raw hash

    }
    if (
        signatureAlgorithm == 16
        || signatureAlgorithm == 17
    ) {
        var pubKeyBitsLength = getKeyLength(signatureAlgorithm);
        var SALT_LEN = HASH_LEN_BITS / 8;
        var E_BITS = getExponentBits(signatureAlgorithm);

        component rsaPss3ShaVerification = VerifyRsaPss3Sig(n, k, SALT_LEN, HASH_LEN_BITS, pubKeyBitsLength);
        rsaPss3ShaVerification.pubkey <== pubKey;
        rsaPss3ShaVerification.signature <== signature;
        rsaPss3ShaVerification.hashed <== hash; // send the raw hash

    }
    if (signatureAlgorithm == 9 
        || signatureAlgorithm == 7 
        || signatureAlgorithm == 8 
        || signatureAlgorithm == 9 
        || signatureAlgorithm == 21 
        || signatureAlgorithm == 22
        || signatureAlgorithm == 23
        || signatureAlgorithm == 24
        || signatureAlgorithm == 25
        || signatureAlgorithm == 26
        || signatureAlgorithm == 27
        || signatureAlgorithm == 28
        || signatureAlgorithm == 29
        || signatureAlgorithm == 30
    ) {
        EcdsaVerifier (signatureAlgorithm, n, k)(signature, pubKey, hash);
    }
}


template HashParser(signatureAlgorithm, n, k) {
    var HASH_LEN_BITS = getHashLength(signatureAlgorithm);
    var msg_len = (HASH_LEN_BITS + n) \ n;

    component hashParser[msg_len];
    signal input hash[HASH_LEN_BITS];

    for (var i = 0; i < msg_len; i++) {
        hashParser[i] = Bits2Num(n);
    }
    for (var i = 0; i < HASH_LEN_BITS; i++) {
        hashParser[i \ n].in[i % n] <== hash[HASH_LEN_BITS - 1 - i];
    }
    for (var i = HASH_LEN_BITS; i < n * msg_len; i++) {
        hashParser[i \ n].in[i % n] <== 0;
    }
    signal output hashParsed[msg_len];
    for (var i = 0; i < msg_len ; i++ ){
        hashParsed[i] <== hashParser[i].out;
    }
}