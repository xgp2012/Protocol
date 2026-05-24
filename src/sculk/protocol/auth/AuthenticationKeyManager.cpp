// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#include "sculk/protocol/auth/AuthenticationKeyManager.hpp"
#include "ssl/ES384.hpp"
#include "ssl/RS256.hpp"
#include <httplib.h>
#include <sculk/reflection/jsonc/reflection.hpp>

namespace sculk::protocol::inline abi_v975 {

constexpr std::string_view MOJANG_PUBLIC_KEY_PEM =
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECRXueJeTDqNRRgJi/vlRufByu/2G0i2Ebt6YMar5QX/R0DIIyrJMcUpruK4QveTfJSTp3Shlq4Gk34cD/"
    "4GUWwkv0DVuzeuB+tXija7HBxii03NHDbPAD0AKnLr2wdAp";

Result<AuthenticationKeyManager::KeyPair> AuthenticationKeyManager::generateRandomES384KeyPair() const {
    std::string privateKeyPem{};
    std::string publicKeyPem{};
    if (!es384::generateES384KeyPair(publicKeyPem, privateKeyPem)) {
        return error_utils::makeError("Failed to generate ES384 key pair");
    }
    return KeyPair{std::move(publicKeyPem), std::move(privateKeyPem)};
}

Result<AuthenticationKeyManager::KeyPair> AuthenticationKeyManager::generateRandomRS256KeyPair() const {
    std::string privateKeyPem{};
    std::string publicKeyPem{};
    if (!rs256::generateRS256KeyPair(publicKeyPem, privateKeyPem)) {
        return error_utils::makeError("Failed to generate RS256 key pair");
    }
    return KeyPair{std::move(publicKeyPem), std::move(privateKeyPem)};
}

Result<> AuthenticationKeyManager::generateAndSetLegacyFullCertificateChainKeyPairs() {
    auto clientResult = generateRandomES384KeyPair();
    if (!clientResult) {
        return error_utils::makeError("Failed to generate ES384 key pair");
    }
    mLegacyCertificateClientKeyPair = std::move(*clientResult);

    auto mojangResult = generateRandomES384KeyPair();
    if (!mojangResult) {
        return error_utils::makeError("Failed to generate ES384 key pair");
    }
    mLegacyCertificateMojangKeyPair = std::move(*mojangResult);

    auto loginResult = generateRandomES384KeyPair();
    if (!loginResult) {
        return error_utils::makeError("Failed to generate ES384 key pair");
    }
    mLegacyCertificateLoginKeyPair = std::move(*loginResult);

    mAuthenticationType = AuthenticationType::Full;
    return {};
}

Result<> AuthenticationKeyManager::generateAndSetLegacySelfSignedCertificateChainKeyPairs() {
    auto loginResult = generateRandomES384KeyPair();
    if (!loginResult) {
        return error_utils::makeError("Failed to generate ES384 key pair");
    }
    mLegacyCertificateLoginKeyPair = std::move(*loginResult);

    mAuthenticationType = AuthenticationType::SelfSigned;
    return {};
}

struct MojangServiceFetchResult {
    struct {
        struct {
            struct {
                struct {
                    std::string serviceUri{};
                    std::string issuer{};
                    std::string playfabTitleId{};
                    std::string eduPlayFabTitleId{};
                } prod;
            } auth;
        } serviceEnvironments;
    } result;
};

struct MojangPublicKeyFetchResult {
    struct KeyInfo {
        std::string kty{};
        std::string use{};
        std::string kid{};
        std::string x5t{};
        std::string n{};
        std::string e{};
    };
    struct {
        std::vector<KeyInfo> keys{};
    } result;
};

Result<> AuthenticationKeyManager::initMojangPublicKeyBlocking() {
    mAuthenticationType = AuthenticationType::Full;
    mValidityLeeway     = std::chrono::seconds(60);
    mLegacyCertificateChainPublicKeyPems.emplace_back(MOJANG_PUBLIC_KEY_PEM);

    // https://client.discovery.minecraft-services.net/api/v1.0/discovery/MinecraftPE/builds/1.0.0.0
    httplib::SSLClient serviceClient("client.discovery.minecraft-services.net");
    httplib::Result    serviceRes = serviceClient.Get("/api/v1.0/discovery/MinecraftPE/builds/1.0.0.0");
    if (!serviceRes || serviceRes->status != 200) {
        return error_utils::makeError("Failed to fetch Mojang service from Internet");
    }
    auto serviceJson = jsonc::json::parse(serviceRes->body);
    if (!serviceJson) {
        return error_utils::makeError("Failed to parse Mojang service response JSON");
    }
    MojangServiceFetchResult fetchResult{};
    if (!reflection::jsonc::deserialize(fetchResult, *serviceJson)) {
        return error_utils::makeError("Failed to deserialize Mojang service response JSON");
    }
    mLoginTokenExpectedIssuer = fetchResult.result.serviceEnvironments.auth.prod.issuer;

    //  {auth service base URL)/.well-known/openid-configuration
    httplib::SSLClient keyClient(fetchResult.result.serviceEnvironments.auth.prod.serviceUri);
    httplib::Result    keyRes = keyClient.Get("/.well-known/openid-configuration");
    if (!keyRes || keyRes->status != 200) {
        return error_utils::makeError("Failed to fetch Mojang public key from Internet");
    }
    auto keyJson = jsonc::json::parse(keyRes->body);
    if (!keyJson) {
        return error_utils::makeError("Failed to parse Mojang public key response JSON");
    }
    MojangPublicKeyFetchResult keyFetchResult{};
    if (!reflection::jsonc::deserialize(keyFetchResult, *keyJson)) {
        return error_utils::makeError("Failed to deserialize Mojang public key response JSON");
    }
    if (keyFetchResult.result.keys.empty()) {
        return error_utils::makeError("Mojang public key response JSON does not contain any keys");
    }
    for (const auto& keyInfo : keyFetchResult.result.keys) {
        if (keyInfo.kty == "RSA" && keyInfo.use == "sig") {
            std::string pem{};
            if (!rs256::jwkRsaPublicKeyToPem(keyInfo.n, keyInfo.e, pem)) {
                return error_utils::makeError("Failed to convert Mojang public key from JWK to PEM format");
            }
            mLoginTokenPublicKeysPemByKeyId.emplace(keyInfo.kid, std::move(pem));
        }
    }

    return {};
}

} // namespace sculk::protocol::inline abi_v975