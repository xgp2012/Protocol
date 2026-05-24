// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#pragma once
#include "AuthenticationType.hpp"
#include "sculk/protocol/utility/Result.hpp"
#include <chrono>
#include <future>
#include <optional>
#include <string>
#include <unordered_map>

namespace sculk::protocol::inline abi_v975 {

class AuthenticationKeyManager {
public:
    struct KeyPair {
        std::string mPublicKeyPem{};
        std::string mPrivateKeyPem{};
    };

private:
    AuthenticationType                                   mAuthenticationType{};
    std::unordered_map<std::string, std::string>         mLoginTokenPublicKeysPemByKeyId{};
    std::optional<std::pair<std::string, KeyPair>>       mLoginTokenKeyPairsAndKeyId{};
    std::string                                          mLoginTokenExpectedIssuer{};
    std::optional<KeyPair>                               mSelfSignedLoginTokenKeyPair{};
    std::vector<std::string>                             mLegacyCertificateChainPublicKeyPems{};
    std::optional<KeyPair>                               mLegacyCertificateClientKeyPair{};
    std::optional<KeyPair>                               mLegacyCertificateMojangKeyPair{};
    std::optional<KeyPair>                               mLegacyCertificateLoginKeyPair{};
    std::chrono::seconds                                 mValidityLeeway{60};
    std::optional<std::chrono::system_clock::time_point> mValidityTime{};
    std::optional<std::chrono::system_clock::time_point> mSigningTime{};

public:
    AuthenticationKeyManager() = default;

    [[nodiscard]] constexpr AuthenticationType getAuthenticationType() const { return mAuthenticationType; }

    [[nodiscard]] constexpr std::chrono::seconds getValidityLeeway() const { return mValidityLeeway; }

    [[nodiscard]] std::chrono::system_clock::time_point getValidityTime() const {
        return mValidityTime.value_or(std::chrono::system_clock::now());
    }

    [[nodiscard]] const std::vector<std::string>& getLegacyCertificateChainPublicKeyPems() const {
        return mLegacyCertificateChainPublicKeyPems;
    }

    [[nodiscard]] std::optional<std::string_view> getLoginTokenPublicKeyPemByKeyId(const std::string& keyId) const {
        auto it = mLoginTokenPublicKeysPemByKeyId.find(keyId);
        if (it != mLoginTokenPublicKeysPemByKeyId.end()) {
            return it->second;
        }
        return {};
    }

    [[nodiscard]] std::string_view getLoginTokenExpectedIssuer() const { return mLoginTokenExpectedIssuer; }

public:
    [[nodiscard]] Result<KeyPair> generateRandomES384KeyPair() const;

    [[nodiscard]] Result<KeyPair> generateRandomRS256KeyPair() const;

public:
    [[nodiscard]] std::chrono::system_clock::time_point getSigningTime() const {
        return mSigningTime.value_or(std::chrono::system_clock::now());
    }

    [[nodiscard]] bool legacyCertificateChainSigningInitialized(AuthenticationType authType) const {
        if (authType == AuthenticationType::Full) {
            return mLegacyCertificateClientKeyPair.has_value() && mLegacyCertificateMojangKeyPair.has_value()
                && mLegacyCertificateLoginKeyPair.has_value();
        } else if (authType == AuthenticationType::SelfSigned) {
            return mLegacyCertificateLoginKeyPair.has_value();
        }
        return false;
    }

    [[nodiscard]] Result<> generateAndSetLegacyFullCertificateChainKeyPairs();

    [[nodiscard]] Result<> generateAndSetLegacySelfSignedCertificateChainKeyPairs();

    constexpr void
    setLegacyCertificateChainClientKeyPair(std::string_view publicKeyPem, std::string_view privateKeyPem) {
        mLegacyCertificateClientKeyPair = KeyPair{std::string(publicKeyPem), std::string(privateKeyPem)};
    }

    constexpr void
    setLegacyCertificateChainMojangKeyPair(std::string_view publicKeyPem, std::string_view privateKeyPem) {
        mLegacyCertificateMojangKeyPair = KeyPair{std::string(publicKeyPem), std::string(privateKeyPem)};
    }

    constexpr void
    setLegacyCertificateChainLoginKeyPair(std::string_view publicKeyPem, std::string_view privateKeyPem) {
        mLegacyCertificateLoginKeyPair = KeyPair{std::string(publicKeyPem), std::string(privateKeyPem)};
    }

    [[nodiscard]] Result<KeyPair> getLegacyCertificateChainClientKeyPair() const {
        if (mLegacyCertificateClientKeyPair) {
            return *mLegacyCertificateClientKeyPair;
        }
        return error_utils::makeError("Client key pair not set");
    }

    [[nodiscard]] Result<KeyPair> getLegacyCertificateChainMojangKeyPair() const {
        if (mLegacyCertificateMojangKeyPair) {
            return *mLegacyCertificateMojangKeyPair;
        }
        return error_utils::makeError("Mojang key pair not set");
    }

    [[nodiscard]] Result<KeyPair> getLegacyCertificateChainLoginKeyPair() const {
        if (mLegacyCertificateLoginKeyPair) {
            return *mLegacyCertificateLoginKeyPair;
        }
        return error_utils::makeError("Login key pair not set");
    }

    [[nodiscard]] bool loginTokenSigningInitialized(AuthenticationType authType) const {
        if (authType == AuthenticationType::Full) {
            return mLoginTokenKeyPairsAndKeyId.has_value();
        } else if (authType == AuthenticationType::SelfSigned) {
            return mSelfSignedLoginTokenKeyPair.has_value();
        }
        return false;
    }

    [[nodiscard]] Result<> generateAndSetLoginTokenKeyPairFull(std::string_view keyId) {
        auto keyPair = generateRandomRS256KeyPair();
        if (!keyPair) {
            return error_utils::makeError("Failed to generate login token key pair");
        }
        mLoginTokenKeyPairsAndKeyId = std::make_pair(std::string(keyId), *keyPair);
        return {};
    }

    [[nodiscard]] Result<> generateAndSetLoginTokenKeyPairSelfSigned() {
        auto keyPair = generateRandomES384KeyPair();
        if (!keyPair) {
            return error_utils::makeError("Failed to generate login token key pair");
        }
        mSelfSignedLoginTokenKeyPair = *keyPair;
        return {};
    }

    constexpr void
    setLoginTokenKeyPairFull(const std::string& keyId, std::string_view publicKeyPem, std::string_view privateKeyPem) {
        mLoginTokenKeyPairsAndKeyId =
            std::make_pair(keyId, KeyPair{std::string(publicKeyPem), std::string(privateKeyPem)});
    }

    constexpr void setLoginTokenKeyPairSelfSigned(std::string_view publicKeyPem, std::string_view privateKeyPem) {
        mSelfSignedLoginTokenKeyPair = KeyPair{std::string(publicKeyPem), std::string(privateKeyPem)};
    }

    [[nodiscard]] Result<KeyPair> getLoginTokenKeyPairFull(std::string& outKeyId) const {
        if (mLoginTokenKeyPairsAndKeyId) {
            outKeyId = mLoginTokenKeyPairsAndKeyId->first;
            return mLoginTokenKeyPairsAndKeyId->second;
        }
        return error_utils::makeError("Login token key pair not set");
    }

    [[nodiscard]] Result<KeyPair> getLoginTokenKeyPairSelfSigned() const {
        if (mSelfSignedLoginTokenKeyPair) {
            return *mSelfSignedLoginTokenKeyPair;
        }
        return error_utils::makeError("Login token key pair not set");
    }

public:
    constexpr void addLoginTokenPublicKeyPemByKeyId(const std::string& keyId, const std::string& publicKeyPem) {
        mLoginTokenPublicKeysPemByKeyId[keyId] = publicKeyPem;
    }

    constexpr void addLegacyCertificateChainPublicKeyPem(std::string_view publicKeyPem) {
        mLegacyCertificateChainPublicKeyPems.emplace_back(publicKeyPem);
    }

public:
    [[nodiscard]] Result<KeyPair> getClientPropertiesKeyPair() const {
        if (mAuthenticationType == AuthenticationType::Full) {
            return getLegacyCertificateChainClientKeyPair();
        } else if (mAuthenticationType == AuthenticationType::SelfSigned) {
            return getLegacyCertificateChainLoginKeyPair();
        }
        return error_utils::makeError("Unsupported authentication type for getting client properties key pair");
    }

public:
    constexpr void setAuthenticationType(AuthenticationType authType) { mAuthenticationType = authType; }

    constexpr void setValidityLeeway(std::chrono::seconds leeway) { mValidityLeeway = leeway; }

    constexpr void setValidityTime(std::chrono::system_clock::time_point validityTime) { mValidityTime = validityTime; }

    constexpr void setSigningTime(std::chrono::system_clock::time_point signingTime) { mSigningTime = signingTime; }

    Result<> initMojangPublicKeyBlocking();

    std::future<Result<>> initMojangPublicKeyAsync() {
        return std::async(std::launch::async, [this]() { return initMojangPublicKeyBlocking(); });
    }
};

} // namespace sculk::protocol::inline abi_v975