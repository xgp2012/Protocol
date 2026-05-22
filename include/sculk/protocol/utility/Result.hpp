// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#pragma once
#include <expected>
#include <string_view>

#ifdef SCULK_PROTOCOL_ENABLE_DETAIL_ERRORS
#include <format>
#include <source_location>
#include <string>
#endif

namespace sculk::protocol::inline abi_v975 {

#ifdef SCULK_PROTOCOL_ENABLE_DETAIL_ERRORS
#define _SCULK_SL_PARAM_DEFAULT , std::source_location location = std::source_location::current()
#define _SCULK_SL_PARAMETER_DEF , std::source_location location
#define _SCULK_SL_PARAM_PASS    , location
#define _SCULK_SL_PARAMETER     , std::source_location
#else
#define _SCULK_SL_PARAM_DEFAULT
#define _SCULK_SL_PARAMETER_DEF
#define _SCULK_SL_PARAM_PASS
#define _SCULK_SL_PARAMETER
#endif

struct ErrorInfo {
#ifdef SCULK_PROTOCOL_ENABLE_DETAIL_ERRORS
    std::source_location mLocation{};
    std::string          mMessage{};
#else
    std::string_view mMessage{};
#endif

#ifdef SCULK_PROTOCOL_ENABLE_DETAIL_ERRORS
    [[nodiscard]] constexpr ErrorInfo(std::string_view message, std::source_location location)
    : mMessage(message),
      mLocation(location) {}

    [[nodiscard]] std::string message() const {
        return std::format(
            "{}\nat file: {} line {} column {}\nin function: {}",
            mMessage,
            mLocation.file_name(),
            mLocation.line(),
            mLocation.column(),
            mLocation.function_name()
        );
    }
#else
    [[nodiscard]] constexpr explicit ErrorInfo(std::string_view message) noexcept : mMessage(message) {}

    [[nodiscard]] std::string_view message() const noexcept { return mMessage; }
#endif
};

template <typename T = void>
using Result = std::expected<T, ErrorInfo>;

namespace error_utils {

#ifdef SCULK_PROTOCOL_ENABLE_DETAIL_ERRORS
[[nodiscard]] constexpr std::unexpected<ErrorInfo>
makeError(std::string_view error, std::source_location location = std::source_location::current()) {
    return std::unexpected(ErrorInfo(error, location));
}
#else
[[nodiscard]] constexpr std::unexpected<ErrorInfo> makeError(std::string_view error) noexcept {
    return std::unexpected(ErrorInfo(error));
}
#endif

} // namespace error_utils

#define _SCULK_READ(expr)                                                                                              \
    if (auto status = expr; !status) return status

} // namespace sculk::protocol::inline abi_v975