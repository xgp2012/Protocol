// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#pragma once
#include "sculk/protocol/utility/Base64Url.hpp"
#include <cstdint>
#include <memory>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <span>
#include <string>
#include <vector>

namespace sculk::protocol::inline abi_v975::rs256 {

constexpr std::size_t MinRsaBits = 2048;

using BioPtr     = std::unique_ptr<BIO, decltype(&BIO_free)>;
using PkeyPtr    = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using MdCtxPtr   = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

[[nodiscard]] inline std::string_view trimPemContent(std::string_view pem) {
    constexpr std::string_view whitespace = " \t\r\n";
    auto                       begin      = pem.find_first_not_of(whitespace);
    if (begin == std::string_view::npos) {
        return {};
    }
    auto end = pem.find_last_not_of(whitespace);
    return pem.substr(begin, end - begin + 1);
}

[[nodiscard]] inline std::string_view normalizePemForRead(std::string_view pem, bool isPrivate, std::string& ownedPem) {
    auto trimmedPem = trimPemContent(pem);
    if (trimmedPem.empty()) {
        return {};
    }

    if (trimmedPem.find("-----BEGIN ") != std::string_view::npos) {
        return trimmedPem;
    }

    ownedPem.clear();
    if (isPrivate) {
        ownedPem.reserve(trimmedPem.size() + 54);
        ownedPem.append("-----BEGIN PRIVATE KEY-----\n");
        ownedPem.append(trimmedPem);
        ownedPem.append("\n-----END PRIVATE KEY-----\n");
    } else {
        ownedPem.reserve(trimmedPem.size() + 52);
        ownedPem.append("-----BEGIN PUBLIC KEY-----\n");
        ownedPem.append(trimmedPem);
        ownedPem.append("\n-----END PUBLIC KEY-----\n");
    }

    return ownedPem;
}

[[nodiscard]] inline bool isRs256Key(const EVP_PKEY* key) {
    return key && EVP_PKEY_base_id(key) == EVP_PKEY_RSA && EVP_PKEY_get_bits(key) >= MinRsaBits;
}

[[nodiscard]] inline MdCtxPtr makeMdCtx() { return MdCtxPtr(EVP_MD_CTX_new(), EVP_MD_CTX_free); }

[[nodiscard]] inline bool generateRS256KeyPair(std::string& outPublicKeyPem, std::string& outPrivateKeyPem) {
    outPublicKeyPem.clear();
    outPrivateKeyPem.clear();

    PkeyCtxPtr pkeyCtx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!pkeyCtx) {
        return false;
    }

    if (EVP_PKEY_keygen_init(pkeyCtx.get()) != 1) {
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkeyCtx.get(), static_cast<int>(MinRsaBits)) != 1) {
        return false;
    }

    EVP_PKEY* rawKey = nullptr;
    if (EVP_PKEY_keygen(pkeyCtx.get(), &rawKey) != 1) {
        return false;
    }

    PkeyPtr key(rawKey, EVP_PKEY_free);
    if (!isRs256Key(key.get())) {
        return false;
    }

    BioPtr publicBio(BIO_new(BIO_s_mem()), BIO_free);
    BioPtr privateBio(BIO_new(BIO_s_mem()), BIO_free);
    if (!publicBio || !privateBio) {
        return false;
    }

    if (PEM_write_bio_PUBKEY(publicBio.get(), key.get()) != 1) {
        return false;
    }
    if (PEM_write_bio_PrivateKey(privateBio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        return false;
    }

    char* publicData  = nullptr;
    long  publicLen   = BIO_get_mem_data(publicBio.get(), &publicData);
    char* privateData = nullptr;
    long  privateLen  = BIO_get_mem_data(privateBio.get(), &privateData);
    if (publicLen <= 0 || privateLen <= 0 || !publicData || !privateData) {
        return false;
    }

    outPublicKeyPem.assign(publicData, static_cast<std::size_t>(publicLen));
    outPrivateKeyPem.assign(privateData, static_cast<std::size_t>(privateLen));
    return true;
}

[[nodiscard]] inline PkeyPtr loadPublicKey(std::string_view pem) {
    std::string      ownedPem{};
    std::string_view normalizedPem = normalizePemForRead(pem, false, ownedPem);
    if (normalizedPem.empty()) {
        return PkeyPtr(nullptr, EVP_PKEY_free);
    }

    BioPtr bio(BIO_new_mem_buf(normalizedPem.data(), static_cast<int>(normalizedPem.size())), BIO_free);
    if (!bio) {
        return PkeyPtr(nullptr, EVP_PKEY_free);
    }

    PkeyPtr key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!isRs256Key(key.get())) {
        return PkeyPtr(nullptr, EVP_PKEY_free);
    }
    return key;
}

[[nodiscard]] inline PkeyPtr loadPrivateKey(std::string_view pem) {
    std::string      ownedPem{};
    std::string_view normalizedPem = normalizePemForRead(pem, true, ownedPem);
    if (normalizedPem.empty()) {
        return PkeyPtr(nullptr, EVP_PKEY_free);
    }

    BioPtr bio(BIO_new_mem_buf(normalizedPem.data(), static_cast<int>(normalizedPem.size())), BIO_free);
    if (!bio) {
        return PkeyPtr(nullptr, EVP_PKEY_free);
    }

    PkeyPtr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!isRs256Key(key.get())) {
        return PkeyPtr(nullptr, EVP_PKEY_free);
    }
    return key;
}

[[nodiscard]] inline bool
verifyRS256Signature(std::string_view signingInput, std::string_view signature, std::string_view publicKeyPem) {
    if (signingInput.empty()) {
        return false;
    }

    auto rawSignature = base64url::decodeChecked(signature);
    if (!rawSignature) {
        return false;
    }

    auto publicKey = loadPublicKey(publicKeyPem);
    if (!publicKey) {
        return false;
    }

    const int expectedSigSize = EVP_PKEY_get_size(publicKey.get());
    if (expectedSigSize <= 0 || rawSignature->size() != static_cast<std::size_t>(expectedSigSize)) {
        return false;
    }

    auto mdCtx = makeMdCtx();
    if (!mdCtx) {
        return false;
    }

    EVP_PKEY_CTX* pkeyCtx = nullptr;
    if (EVP_DigestVerifyInit(mdCtx.get(), &pkeyCtx, EVP_sha256(), nullptr, publicKey.get()) != 1) {
        return false;
    }

    if (!pkeyCtx || EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PADDING) != 1) {
        return false;
    }

    if (EVP_DigestVerifyUpdate(mdCtx.get(), signingInput.data(), signingInput.size()) != 1) {
        return false;
    }

    return EVP_DigestVerifyFinal(
               mdCtx.get(),
               reinterpret_cast<const std::uint8_t*>(rawSignature->data()),
               rawSignature->size()
           )
        == 1;
}

[[nodiscard]] inline bool
signRS256Signature(std::string_view signingInput, std::string_view privateKeyPem, std::string& outSignature) {
    outSignature.clear();

    if (signingInput.empty()) {
        return false;
    }

    auto privateKey = loadPrivateKey(privateKeyPem);
    if (!privateKey) {
        return false;
    }

    auto mdCtx = makeMdCtx();
    if (!mdCtx) {
        return false;
    }

    EVP_PKEY_CTX* pkeyCtx = nullptr;
    if (EVP_DigestSignInit(mdCtx.get(), &pkeyCtx, EVP_sha256(), nullptr, privateKey.get()) != 1) {
        return false;
    }

    if (!pkeyCtx || EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PADDING) != 1) {
        return false;
    }

    if (EVP_DigestSignUpdate(mdCtx.get(), signingInput.data(), signingInput.size()) != 1) {
        return false;
    }

    std::size_t signatureLen = 0;
    if (EVP_DigestSignFinal(mdCtx.get(), nullptr, &signatureLen) != 1 || signatureLen == 0) {
        return false;
    }

    std::vector<std::uint8_t> rawSignature(signatureLen);
    if (EVP_DigestSignFinal(mdCtx.get(), rawSignature.data(), &signatureLen) != 1) {
        return false;
    }
    rawSignature.resize(signatureLen);

    outSignature = base64url::encode(std::span<const std::uint8_t>(rawSignature));
    return true;
}

} // namespace sculk::protocol::inline abi_v975::rs256
