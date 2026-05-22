// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#pragma once
#include "AuthenticationKeyManager.hpp"
#include "AuthenticationType.hpp"
#include "ClientProperties.hpp"
#include "LegacyCertificateChain.hpp"
#include "LoginToken.hpp"
#include "sculk/protocol/utility/Result.hpp"
#include <optional>
#include <string>

namespace sculk::protocol::inline abi_v975 {

class ConnectionRequest {
public:
    AuthenticationType                    mAuthenticationType{};
    std::optional<LegacyCertificateChain> mLegacyCertificateChain{};
    std::optional<LoginToken>             mLoginToken{};
    ClientProperties                      mClientProperties{};

public:
    [[nodiscard]] Result<> verify(const AuthenticationKeyManager& publicKeyManager) const;

    [[nodiscard]] std::string toString() const;

public:
    [[nodiscard]] static Result<ConnectionRequest> fromString(std::string_view rawRequest);

    [[nodiscard]] static Result<ConnectionRequest> create(
        AuthenticationType           authenticationType,
        std::optional<std::string>&& legacyCertificateChainString,
        std::optional<std::string>&& loginTokenString,
        std::string&&                clientPropertiesString
    );
};

} // namespace sculk::protocol::inline abi_v975
