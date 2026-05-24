// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#pragma once
#include "AUthenticationKeyManager.hpp"
#include "sculk/protocol/utility/Result.hpp"
#include <format>
#include <optional>
#include <string>

namespace sculk::protocol::inline abi_v975 {

class LoginToken {
public:
    struct Header {
        std::string                alg{};
        std::optional<std::string> kid{};
        std::optional<std::string> x5u{};
        std::optional<std::string> typ{};
    };

    struct Payload {
        std::optional<std::string>  sub{};
        std::optional<std::string>  ipt{};
        std::optional<std::int64_t> iat{};
        std::string                 mid{};
        std::optional<std::string>  tid{};
        std::optional<std::string>  pfcd{};
        std::string                 cpk{};
        int                         ap{};
        std::string                 xid{};
        std::string                 xname{};
        std::int64_t                exp{};
        std::optional<std::string>  iss{};
        std::string                 aud{};
        std::optional<std::string>  leguuid{};
        std::optional<std::string>  nid{};
        std::optional<std::string>  nname{};
        std::optional<std::string>  pid{};
        std::optional<std::string>  pname{};
    };

public:
    std::string mRawHeader{};
    Header      mHeader{};
    std::string mRawPayload{};
    Payload     mPayload{};
    std::string mSignature{};

public:
    [[nodiscard]] std::string getClientPublicKey() const { return mPayload.cpk; }

    [[nodiscard]] std::string_view getMinecraftID() const { return mPayload.mid; }

    [[nodiscard]] std::string_view getXboxName() const { return mPayload.xname; }

    [[nodiscard]] std::string_view getXUID() const { return mPayload.xid; }

public:
    [[nodiscard]] Result<> verify(const AuthenticationKeyManager& authenticationKeyManager) const;

    [[nodiscard]] Result<> signFull(const AuthenticationKeyManager& authenticationKeyManager);

    [[nodiscard]] Result<> signSelfSigned(const AuthenticationKeyManager& authenticationKeyManager);

    [[nodiscard]] Result<> sign(const AuthenticationKeyManager& authenticationKeyManager);

    [[nodiscard]] std::string toString() const { return std::format("{}.{}.{}", mRawHeader, mRawPayload, mSignature); }

public:
    [[nodiscard]] static Result<LoginToken> fromString(std::string_view rawLoginToken);
};

} // namespace sculk::protocol::inline abi_v975