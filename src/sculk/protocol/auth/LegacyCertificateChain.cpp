// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#include "sculk/protocol/auth/LegacyCertificateChain.hpp"
#include "sculk/reflection/jsonc/reflection.hpp"
#include "ssl/ES384.hpp"

namespace sculk::protocol::inline abi_v975 {

#define SCULK_CERTIFICATE_SERIALIZE_OPTION_INIT() static reflection::jsonc::options options{.indent = -1}

#define SCULK_CERTIFICATE_CREATE_JSON(PART, DATA)                                                                      \
    jsonc::json PART##Json = jsonc::json::object();                                                                    \
    const auto& PART       = DATA;

#define SCULK_CERTIFICATE_SERIALIZE(PART, FIELD)                                                                       \
    auto FIELD = reflection::jsonc::serialize<false, false>(PART.FIELD, options);                                      \
    if (!FIELD.is_null()) {                                                                                            \
        PART##Json[#FIELD] = FIELD;                                                                                    \
    }

#define SCULK_CERTIFICATE_PARSE_JSON(PART, RAW)                                                                        \
    auto PART##JsonStr = base64url::decodeChecked(RAW);                                                                \
    if (!PART##JsonStr) {                                                                                              \
        return error_utils::makeError("Failed to decode certificate " #PART);                                          \
    }                                                                                                                  \
    auto PART##JsonOpt = jsonc::json::parse(*PART##JsonStr);                                                           \
    if (!PART##JsonOpt) {                                                                                              \
        return error_utils::makeError("Failed to parse certificate " #PART " JSON");                                   \
    }                                                                                                                  \
    const auto& PART##Json = *PART##JsonOpt;

#define SCULK_CERTIFICATE_DESERIALIZE(PART, FIELD)                                                                     \
    if (!PART##Json.contains(#FIELD)) {                                                                                \
        return error_utils::makeError("Certificate JSON does not contain a valid field '" #FIELD "'");                 \
    }                                                                                                                  \
    if (!reflection::jsonc::deserialize<false, false>(PART.FIELD, PART##Json[#FIELD], options)) {                      \
        return error_utils::makeError("Failed to deserialize certificate " #PART " field '" #FIELD "'");               \
    }

bool Certificate::verify(std::string_view publicKeyPem) const {
    std::string signingInput = std::format("{}.{}", mRawHeader, mRawPayload);
    return es384::verifyES384Signature(signingInput, mSignature, publicKeyPem);
}

bool Certificate::sign(std::string_view privateKeyPem, std::chrono::system_clock::time_point now) {
    mPayload.exp =
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch() + std::chrono::hours(3)).count();
    mPayload.nbf = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    if (mPayload.iat.has_value()) {
        mPayload.iat = mPayload.nbf;
    }

    SCULK_CERTIFICATE_SERIALIZE_OPTION_INIT();

    SCULK_CERTIFICATE_CREATE_JSON(header, mHeader);
    SCULK_CERTIFICATE_SERIALIZE(header, alg);
    SCULK_CERTIFICATE_SERIALIZE(header, x5u);
    SCULK_CERTIFICATE_SERIALIZE(header, x5t);
    mRawHeader = base64url::encode(headerJson.dump());

    SCULK_CERTIFICATE_CREATE_JSON(payload, mPayload);
    SCULK_CERTIFICATE_SERIALIZE(payload, nbf);
    SCULK_CERTIFICATE_SERIALIZE(payload, exp);
    SCULK_CERTIFICATE_SERIALIZE(payload, identityPublicKey);
    SCULK_CERTIFICATE_SERIALIZE(payload, certificateAuthority);
    SCULK_CERTIFICATE_SERIALIZE(payload, randomNonce);
    SCULK_CERTIFICATE_SERIALIZE(payload, iss);
    SCULK_CERTIFICATE_SERIALIZE(payload, iat);
    SCULK_CERTIFICATE_SERIALIZE(payload, extraData);
    mRawPayload = base64url::encode(payloadJson.dump());

    std::string signingInput = std::format("{}.{}", mRawHeader, mRawPayload);
    return es384::signES384Signature(signingInput, privateKeyPem, mSignature);
}

Result<Certificate> Certificate::fromString(std::string_view certificateStr) {
    SCULK_CERTIFICATE_SERIALIZE_OPTION_INIT();

    const auto first = certificateStr.find('.');
    const auto last  = certificateStr.rfind('.');

    if (first == std::string::npos || last == std::string::npos || first == last) {
        return error_utils::makeError("Invalid certificate format: expected three parts separated by dots");
    }

    auto   rawHeader = certificateStr.substr(0, first);
    Header header{};
    SCULK_CERTIFICATE_PARSE_JSON(header, rawHeader);
    SCULK_CERTIFICATE_DESERIALIZE(header, alg);
    if (header.alg != "ES384") {
        return error_utils::makeError("certificate signing algorithm must be ES384");
    }
    SCULK_CERTIFICATE_DESERIALIZE(header, x5u);
    SCULK_CERTIFICATE_DESERIALIZE(header, x5t);

    auto    rawPayload = certificateStr.substr(first + 1, last - first - 1);
    Payload payload{};
    SCULK_CERTIFICATE_PARSE_JSON(payload, rawPayload);
    SCULK_CERTIFICATE_DESERIALIZE(payload, nbf);
    SCULK_CERTIFICATE_DESERIALIZE(payload, exp);
    SCULK_CERTIFICATE_DESERIALIZE(payload, identityPublicKey);
    SCULK_CERTIFICATE_DESERIALIZE(payload, certificateAuthority);
    SCULK_CERTIFICATE_DESERIALIZE(payload, randomNonce);
    SCULK_CERTIFICATE_DESERIALIZE(payload, iss);
    SCULK_CERTIFICATE_DESERIALIZE(payload, iat);
    SCULK_CERTIFICATE_DESERIALIZE(payload, extraData);

    auto signature = certificateStr.substr(last + 1);

    return Certificate{
        .mRawHeader  = std::string(rawHeader),
        .mHeader     = std::move(header),
        .mRawPayload = std::string(rawPayload),
        .mPayload    = std::move(payload),
        .mSignature  = std::string(signature)
    };
}


std::string LegacyCertificateChain::toString() const {
    jsonc::json certChainJson = {
        {"chain", jsonc::json::array({})}
    };
    if (mClientCertificate) {
        certChainJson["chain"].push_back(mClientCertificate->toString());
    }
    if (mMojangCertificate) {
        certChainJson["chain"].push_back(mMojangCertificate->toString());
    }
    certChainJson["chain"].push_back(mLoginCertificate.toString());
    return certChainJson.dump();
}

Result<> LegacyCertificateChain::verify(const AuthenticationKeyManager& authenticationKeyManager) const {
    const bool hasClient = mClientCertificate.has_value();
    const bool hasMojang = mMojangCertificate.has_value();

    auto now          = std::chrono::system_clock::now();
    auto leeway       = authenticationKeyManager.getValidityLeeway();
    auto publicKeyPem = authenticationKeyManager.getLegacyCertificateChainPublicKeyPem();

    if (hasClient && hasMojang) {
        const auto& clientCert = *mClientCertificate;
        const auto& mojangCert = *mMojangCertificate;
        const auto& loginCert  = mLoginCertificate;

        if (clientCert.mHeader.x5u != loginCert.mPayload.identityPublicKey) {
            return error_utils::makeError("Client certificate does not match login certificate");
        }
        if (!clientCert.checkTimeValidity(leeway, now)) {
            return error_utils::makeError("Client certificate time validity check failed");
        }
        if (!clientCert.verify(clientCert.mHeader.x5u)) {
            return error_utils::makeError("Client certificate signature verification failed");
        }

        if (mojangCert.mHeader.x5u != clientCert.mPayload.identityPublicKey) {
            return error_utils::makeError("Mojang certificate does not match client certificate");
        }
        if (mojangCert.mHeader.x5u != publicKeyPem) {
            return error_utils::makeError("Mojang certificate does not match provided public key");
        }
        if (!mojangCert.checkTimeValidity(leeway, now)) {
            return error_utils::makeError("Mojang certificate time validity check failed");
        }
        if (!mojangCert.checkIssuer("Mojang")) {
            return error_utils::makeError("Mojang certificate issuer check failed");
        }
        if (!mojangCert.verify(publicKeyPem)) {
            return error_utils::makeError("Mojang certificate signature verification failed");
        }

        if (loginCert.mHeader.x5u != mojangCert.mPayload.identityPublicKey) {
            return error_utils::makeError("Login certificate does not match mojang certificate");
        }
        if (!loginCert.checkTimeValidity(leeway, now)) {
            return error_utils::makeError("Login certificate time validity check failed");
        }
        if (!loginCert.checkIssuer("Mojang")) {
            return error_utils::makeError("Login certificate issuer check failed");
        }
        if (!loginCert.verify(loginCert.mHeader.x5u)) {
            return error_utils::makeError("Login certificate signature verification failed");
        }
    } else if (!hasClient && !hasMojang) {
        const auto& loginCert = mLoginCertificate;

        if (!loginCert.checkTimeValidity(leeway, now)) {
            return error_utils::makeError("Login certificate time validity check failed");
        }
        if (!loginCert.verify(loginCert.mHeader.x5u)) {
            return error_utils::makeError("Login certificate signature verification failed");
        }
    }

    return {};
}

Result<> LegacyCertificateChain::signFull(
    std::string_view                      privateKeyPem,
    std::string_view                      publicKeyPem,
    std::chrono::system_clock::time_point now
) {
    if (!mClientCertificate.has_value() || !mMojangCertificate.has_value()) {
        return error_utils::makeError("Missing client or Mojang certificate");
    }

    std::string publicKey1{};
    std::string privateKey1{};
    if (!es384::generateES384KeyPair(publicKey1, privateKey1)) {
        return error_utils::makeError("Failed to generate key pair for client certificate");
    }
    std::string publicKey3{};
    std::string privateKey3{};
    if (!es384::generateES384KeyPair(publicKey3, privateKey3)) {
        return error_utils::makeError("Failed to generate key pair for login certificate");
    }

    mClientCertificate->mHeader.x5u                = publicKey1;
    mClientCertificate->mPayload.identityPublicKey = publicKey3;
    if (!mClientCertificate->sign(privateKey1, now)) {
        return error_utils::makeError("Failed to sign client certificate");
    }

    mMojangCertificate->mHeader.x5u                = publicKeyPem;
    mMojangCertificate->mPayload.identityPublicKey = publicKey1;
    if (!mMojangCertificate->sign(privateKeyPem, now)) {
        return error_utils::makeError("Failed to sign Mojang certificate");
    }

    mLoginCertificate.mHeader.x5u                = publicKey3;
    mLoginCertificate.mPayload.identityPublicKey = publicKeyPem;
    if (!mLoginCertificate.sign(privateKey3, now)) {
        return error_utils::makeError("Failed to sign login certificate");
    }

    return {};
}

Result<> LegacyCertificateChain::signSelfSigned(
    std::string_view                      privateKeyPem,
    std::string_view                      publicKeyPem,
    std::chrono::system_clock::time_point now
) {
    mClientCertificate.reset();
    mMojangCertificate.reset();

    mLoginCertificate.mHeader.x5u                = publicKeyPem;
    mLoginCertificate.mPayload.identityPublicKey = publicKeyPem;
    if (!mLoginCertificate.sign(privateKeyPem, now)) {
        return error_utils::makeError("Failed to sign login certificate");
    }

    return {};
}

Result<> LegacyCertificateChain::sign(const AuthenticationKeyManager& publicKeyManager) {
    auto now      = publicKeyManager.getCurrentTime();
    auto authType = publicKeyManager.getAuthenticationType();
    if (authType == AuthenticationType::Full) {
        return signFull(
            publicKeyManager.getLegacyCertificateChainPrivateKeyPem(),
            publicKeyManager.getLegacyCertificateChainPublicKeyPem(),
            now
        );
    } else if (authType == AuthenticationType::SelfSigned) {
        return signSelfSigned(
            publicKeyManager.getLegacyCertificateChainPrivateKeyPem(),
            publicKeyManager.getLegacyCertificateChainPublicKeyPem(),
            now
        );
    }
    return error_utils::makeError("Unsupported authentication type for signing");
}

#ifdef SCULK_PROTOCOL_ENABLE_DETAIL_ERRORS
#define SCULK_CERTIFICATE_PARSE(PART, INDEX)                                                                           \
    if (!certJson["chain"][INDEX].is_string()) {                                                                       \
        return error_utils::makeError("Certificate JSON 'chain' field must be an array of strings");                   \
    }                                                                                                                  \
    auto PART##CertStr = certJson["chain"][INDEX].get<std::string>();                                                  \
    auto PART##CertOpt = Certificate::fromString(PART##CertStr);                                                       \
    if (!PART##CertOpt) {                                                                                              \
        return error_utils::makeError(                                                                                 \
            std::format("Failed to parse {} certificate: {}", #PART, PART##CertOpt.error().mMessage)                   \
        );                                                                                                             \
    }                                                                                                                  \
    auto PART##Cert = *PART##CertOpt;
#else
#define SCULK_CERTIFICATE_PARSE(PART, INDEX)                                                                           \
    if (!certJson["chain"][INDEX].is_string()) {                                                                       \
        return error_utils::makeError("Certificate JSON 'chain' field must be an array of strings");                   \
    }                                                                                                                  \
    auto PART##CertStr = certJson["chain"][INDEX].get<std::string>();                                                  \
    auto PART##CertOpt = Certificate::fromString(PART##CertStr);                                                       \
    if (!PART##CertOpt) {                                                                                              \
        return error_utils::makeError("Failed to parse " #PART " certificate");                                        \
    }                                                                                                                  \
    auto PART##Cert = *PART##CertOpt;
#endif

#define SCULK_CERTIFICATE_CHECK_HEADER(PART, FIELD)                                                                    \
    if (!PART##Cert.mHeader.FIELD.has_value()) {                                                                       \
        return error_utils::makeError(#PART " certificate does not contain a valid '" #FIELD "' header field");        \
    }

#define SCULK_CERTIFICATE_CHECK_PAYLOAD(PART, FIELD)                                                                   \
    if (!PART##Cert.mPayload.FIELD.has_value()) {                                                                      \
        return error_utils::makeError(#PART " certificate does not contain a valid '" #FIELD "' payload field");       \
    }

Result<LegacyCertificateChain> LegacyCertificateChain::fromString(std::string_view certificateChainJsonStr) {
    auto certJsonOpt = jsonc::json::parse(certificateChainJsonStr);
    if (!certJsonOpt) {
        return error_utils::makeError("Failed to parse certificate chain JSON");
    }

    const auto& certJson = *certJsonOpt;
    if (!certJson.contains("chain") || !certJson["chain"].is_array()) {
        return error_utils::makeError("Certificate JSON does not contain a valid 'chain' field");
    }

    std::size_t certCount = certJson["chain"].size();
    if (certCount == 1) {
        SCULK_CERTIFICATE_PARSE(login, 0);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(login, extraData);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(login, randomNonce);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(login, iss);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(login, iat);
        return LegacyCertificateChain{.mLoginCertificate = std::move(*loginCertOpt)};
    } else if (certCount == 3) {
        SCULK_CERTIFICATE_PARSE(client, 0);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(client, certificateAuthority);
        SCULK_CERTIFICATE_PARSE(mojang, 1);
        SCULK_CERTIFICATE_CHECK_HEADER(mojang, x5t);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(mojang, certificateAuthority);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(mojang, randomNonce);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(mojang, iss);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(mojang, iat);
        SCULK_CERTIFICATE_PARSE(login, 2);
        SCULK_CERTIFICATE_CHECK_HEADER(login, x5t);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(login, extraData);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(login, randomNonce);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(login, iss);
        SCULK_CERTIFICATE_CHECK_PAYLOAD(login, iat);
        return LegacyCertificateChain{
            .mClientCertificate = std::move(*clientCertOpt),
            .mMojangCertificate = std::move(*mojangCertOpt),
            .mLoginCertificate  = std::move(*loginCertOpt)
        };
    }
    return error_utils::makeError("Certificate JSON 'chain' field must contain either 1 or 3 certificates");
}

} // namespace sculk::protocol::inline abi_v975
