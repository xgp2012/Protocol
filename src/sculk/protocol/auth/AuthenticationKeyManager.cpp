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

Result<> AuthenticationKeyManager::initMojangPublicKeyBlocking() {
    mAuthenticationType                 = AuthenticationType::Full;
    mLegacyCertificateChainPublicKeyPem = MOJANG_PUBLIC_KEY_PEM;
    mValidityLeeway                     = std::chrono::seconds(60);
    // TODO: RS256 token
    return {};
}

} // namespace sculk::protocol::inline abi_v975