// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#include "sculk/protocol/auth/AuthenticationKeyManager.hpp"
#include <httplib.h>

namespace sculk::protocol::inline abi_v975 {

constexpr std::string_view MOJANG_PUBLIC_KEY_PEM =
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECRXueJeTDqNRRgJi/vlRufByu/2G0i2Ebt6YMar5QX/R0DIIyrJMcUpruK4QveTfJSTp3Shlq4Gk34cD/"
    "4GUWwkv0DVuzeuB+tXija7HBxii03NHDbPAD0AKnLr2wdAp";

Result<> AuthenticationKeyManager::initMojangPublicKey() {
    mAuthenticationType                 = AuthenticationType::Full;
    mLegacyCertificateChainPublicKeyPem = MOJANG_PUBLIC_KEY_PEM;
    mValidityLeeway                     = std::chrono::seconds(60);
    // TODO: RS256 token
    return {};
}

} // namespace sculk::protocol::inline abi_v975