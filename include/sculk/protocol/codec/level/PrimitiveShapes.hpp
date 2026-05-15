// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#pragma once
#include "sculk/protocol/codec/utility/deps/BinaryStream.hpp"
#include "sculk/protocol/codec/utility/deps/ReadOnlyBinaryStream.hpp"
#include "sculk/protocol/codec/utility/math/Vec3.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <variant>

namespace sculk::protocol::inline abi_v975 {

enum class PrimitiveShapesType : std::uint8_t {
    Line          = 0,
    Box           = 1,
    Sphere        = 2,
    Circle        = 3,
    Text          = 4,
    Arrow         = 5,
    NumShapeTypes = 6,
};

struct PrimitiveArrow {
    std::optional<Vec3>         mArrowEndLocation{};
    std::optional<float>        mArrowHeadLength{};
    std::optional<float>        mArrowHeadRadius{};
    std::optional<std::uint8_t> mArrowSegments{};
};

struct PrimitiveBox {
    Vec3 mBoxBound{};
};

struct PrimitiveSegments {
    std::uint8_t mSegments{};
};

struct PrimitiveLine {
    Vec3 mLineEndLocation{};
};

struct PrimitiveText {
    std::string        mText{};
    bool               mUseRotation{};
    std::optional<int> mBackgroundColor{};
    bool               mDepthTest{};
    bool               mShowBackface{};
    bool               mShowTextBackface{};
};

using PrimitiveShapesVariant =
    std::variant<std::monostate, PrimitiveArrow, PrimitiveText, PrimitiveBox, PrimitiveLine, PrimitiveSegments>;

struct PrimitiveShapes {
    std::uint64_t                      mNetworkId{};
    std::optional<Vec3>                mLocation{};
    std::optional<PrimitiveShapesType> mType{};
    std::optional<std::int32_t>        mDimensionId{};
    std::optional<float>               mScale{};
    std::optional<Vec3>                mRotation{};
    std::optional<float>               mTotalTimeLeft{};
    std::optional<float>               mMaxRenderDistance{};
    std::optional<std::int32_t>        mColor{};
    std::optional<std::int64_t>        mAttachedToEntityId{};
    PrimitiveShapesVariant             mShape{};

    void write(BinaryStream& stream) const;

    [[nodiscard]] Result<> read(ReadOnlyBinaryStream& stream);
};

} // namespace sculk::protocol::inline abi_v975
