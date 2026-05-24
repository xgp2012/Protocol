// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#include "sculk/protocol/auth/ConnectionRequest.hpp"
#include "sculk/protocol/utility/Base64Url.hpp"
#include "sculk/protocol/utility/BinaryStream.hpp"
#include "sculk/protocol/utility/ReadOnlyBinaryStream.hpp"
#include <sculk/reflection/jsonc/reflection.hpp>

namespace sculk::reflection::jsonc {
template <>
struct serializer<sculk::protocol::AuthenticationType> {
    static int to_signed(const sculk::protocol::AuthenticationType& t) { return static_cast<int>(t); }
    static std::optional<sculk::protocol::AuthenticationType> from_signed(int v) {
        if (v < static_cast<int>(sculk::protocol::AuthenticationType::Full)
            || v > static_cast<int>(sculk::protocol::AuthenticationType::SelfSigned)) {
            return std::nullopt;
        }
        return static_cast<sculk::protocol::AuthenticationType>(v);
    }
};
} // namespace sculk::reflection::jsonc

namespace sculk::protocol::inline abi_v975 {

Result<> ConnectionRequest::verify(const AuthenticationKeyManager& authenticationKeyManager) const {
    if (mLoginToken) {
        if (!mLoginToken->verify(authenticationKeyManager)) {
            return error_utils::makeError("Login token verification failed");
        }
        return mClientProperties.verify(mLoginToken->getClientPublicKey());
    }

    if (mLegacyCertificateChain) {
        if (!mLegacyCertificateChain->verify(authenticationKeyManager)) {
            return error_utils::makeError("Legacy certificate chain verification failed");
        }
        return mClientProperties.verify(mLegacyCertificateChain->getClientPublicKey());
    }

    return error_utils::makeError("ConnectionRequest must have either a login token or a legacy certificate chain");
}

Result<> ConnectionRequest::sign(const AuthenticationKeyManager& authenticationKeyManager) {
    if (!mLoginToken && !mLegacyCertificateChain) {
        return error_utils::makeError(
            "ConnectionRequest must have either a login token or a legacy certificate chain to sign"
        );
    }

    if (mLoginToken && authenticationKeyManager.loginTokenSigningInitialized(mAuthenticationType)) {
        if (!mLoginToken->sign(authenticationKeyManager)) {
            return error_utils::makeError("Login token signing failed");
        }
    }

    if (mLegacyCertificateChain
        && authenticationKeyManager.legacyCertificateChainSigningInitialized(mAuthenticationType)) {
        if (!mLegacyCertificateChain->sign(authenticationKeyManager)) {
            return error_utils::makeError("Legacy certificate chain signing failed");
        }
    }

    return {};
}

std::string ConnectionRequest::toString() const {
    std::vector<std::byte> buffer{};
    BinaryStream           stream(buffer);

    jsonc::json authJson = {
        {"AuthenticationType", static_cast<int>(mAuthenticationType)     },
        {"Token",              mLoginToken ? mLoginToken->toString() : ""}
    };
    if (mLegacyCertificateChain) {
        authJson["Certificate"] = mLegacyCertificateChain->toString();
    }

    stream.writeLongString(authJson.dump(-1));
    stream.writeLongString(mClientProperties.toString());

    std::string result{};
    result.resize_and_overwrite(buffer.size(), [&buffer](char* data, std::size_t size) {
        std::memcpy(data, buffer.data(), size);
        return size;
    });

    return result;
}

#define SCULK_CONNECTION_REQUEST_DESERIALIZE(FIELD_NAME, VALUE)                                                        \
    if (!authJson.contains(FIELD_NAME)) {                                                                              \
        return error_utils::makeError("Authentication JSON does not contain a valid '" FIELD_NAME "' field");          \
    }                                                                                                                  \
    if (!reflection::jsonc::deserialize<false, false>(VALUE, authJson[FIELD_NAME], options)) {                         \
        return error_utils::makeError("Failed to deserialize '" FIELD_NAME "' field in authentication JSON");          \
    }

Result<ConnectionRequest> ConnectionRequest::fromString(std::string_view rawRequest) {
    ReadOnlyBinaryStream stream(rawRequest);

    std::string authJsonStr{};
    if (!stream.readLongString(authJsonStr)) {
        return error_utils::makeError("Read ConnectionRequest authentication JSON overflowed");
    }

    auto authJsonOpt = jsonc::json::parse(authJsonStr);
    if (!authJsonOpt) {
        return error_utils::makeError("Failed to parse authentication JSON from ConnectionRequest");
    }

    const auto&                       authJson = *authJsonOpt;
    static reflection::jsonc::options options{.indent = -1, .allow_trailing_comma = false};

    AuthenticationType authType{};
    SCULK_CONNECTION_REQUEST_DESERIALIZE("AuthenticationType", authType);
    std::optional<std::string> legacyCertificate{};
    SCULK_CONNECTION_REQUEST_DESERIALIZE("Certificate", legacyCertificate);
    std::string loginToken{};
    SCULK_CONNECTION_REQUEST_DESERIALIZE("Token", loginToken);

    std::string clientProperties{};
    if (!stream.readLongString(clientProperties)) {
        return error_utils::makeError("Read ConnectionRequest client properties overflowed");
    }

    return ConnectionRequest::create(
        authType,
        std::move(legacyCertificate),
        loginToken.empty() ? std::nullopt : std::make_optional(std::move(loginToken)),
        std::move(clientProperties)
    );
}

Result<ConnectionRequest> ConnectionRequest::create(
    AuthenticationType           authenticationType,
    std::optional<std::string>&& legacyCertificateChainString,
    std::optional<std::string>&& loginTokenString,
    std::string&&                clientPropertiesString
) {
    std::optional<LegacyCertificateChain> legacyCertificateChain{};
    if (legacyCertificateChainString && *legacyCertificateChainString != "{\"chain\":[\"..\"]}\n") {
        auto certChain = LegacyCertificateChain::fromString(*legacyCertificateChainString);
        if (!certChain) {
            return error_utils::makeError("Failed to parse legacy certificate chain");
        }
        legacyCertificateChain = std::move(*certChain);
    }

    std::optional<LoginToken> loginToken{};
    if (loginTokenString) {
        auto token = LoginToken::fromString(*loginTokenString);
        if (!token) {
            return error_utils::makeError("Failed to parse login token");
        }
        loginToken = std::move(*token);
    }

    if (!legacyCertificateChain && !loginToken) {
        return error_utils::makeError("ConnectionRequest must have either a legacy certificate chain or a login token");
    }

    auto clientProperties = ClientProperties::fromString(std::move(clientPropertiesString));
    if (!clientProperties) {
        return error_utils::makeError("Failed to parse client properties");
    }

    return ConnectionRequest{
        .mAuthenticationType     = authenticationType,
        .mLegacyCertificateChain = std::move(legacyCertificateChain),
        .mLoginToken             = std::move(loginToken),
        .mClientProperties       = std::move(*clientProperties)
    };
}

} // namespace sculk::protocol::inline abi_v975
