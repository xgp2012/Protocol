// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#include "sculk/protocol/codec/camera/CameraInstruction.hpp"
#include "../utility/EnumName.hpp"

namespace sculk::protocol::inline abi_v975 {

void CameraInstruction::FadeInstruction::TimeOption::write(BinaryStream& stream) const {
    stream.writeFloat(mFadeInTime);
    stream.writeFloat(mHoldTime);
    stream.writeFloat(mFadeOutTime);
}

Result<> CameraInstruction::FadeInstruction::TimeOption::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(stream.readFloat(mFadeInTime));
    _SCULK_READ(stream.readFloat(mHoldTime));
    return stream.readFloat(mFadeOutTime);
}

void CameraInstruction::FadeInstruction::ColorOption::write(BinaryStream& stream) const {
    stream.writeFloat(mRed);
    stream.writeFloat(mGreen);
    stream.writeFloat(mBlue);
}

Result<> CameraInstruction::FadeInstruction::ColorOption::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(stream.readFloat(mRed));
    _SCULK_READ(stream.readFloat(mGreen));
    return stream.readFloat(mBlue);
}

void CameraInstruction::FadeInstruction::write(BinaryStream& stream) const {
    stream.writeOptional(mTime, &TimeOption::write);
    stream.writeOptional(mColor, &ColorOption::write);
}

Result<> CameraInstruction::FadeInstruction::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(stream.readOptional(mTime, &TimeOption::read));
    return stream.readOptional(mColor, &ColorOption::read);
}

void CameraInstruction::SetInstruction::EaseOption::write(BinaryStream& stream) const {
    stream.writeEnum(mEasingType, &BinaryStream::writeByte);
    stream.writeFloat(mEasingTime);
}

Result<> CameraInstruction::SetInstruction::EaseOption::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(stream.readEnum(mEasingType, &ReadOnlyBinaryStream::readByte));
    return stream.readFloat(mEasingTime);
}

void CameraInstruction::SetInstruction::write(BinaryStream& stream) const {
    stream.writeUnsignedInt(mPresetIndex);
    stream.writeOptional(mEase, &EaseOption::write);
    stream.writeOptional(mPos, &Vec3::write);
    stream.writeOptional(mRot, &Vec2::write);
    stream.writeOptional(mFacing, &Vec3::write);
    stream.writeOptional(mViewOffset, &Vec2::write);
    stream.writeOptional(mEntityOffset, &Vec3::write);
    stream.writeOptional(mDefault, &BinaryStream::writeBool);
    stream.writeBool(mRemoveIgnoreStartingValuesComponent);
}

Result<> CameraInstruction::SetInstruction::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(stream.readUnsignedInt(mPresetIndex));
    _SCULK_READ(stream.readOptional(mEase, &EaseOption::read));
    _SCULK_READ(stream.readOptional(mPos, &Vec3::read));
    _SCULK_READ(stream.readOptional(mRot, &Vec2::read));
    _SCULK_READ(stream.readOptional(mFacing, &Vec3::read));
    _SCULK_READ(stream.readOptional(mViewOffset, &Vec2::read));
    _SCULK_READ(stream.readOptional(mEntityOffset, &Vec3::read));
    _SCULK_READ(stream.readOptional(mDefault, &ReadOnlyBinaryStream::readBool));
    return stream.readBool(mRemoveIgnoreStartingValuesComponent);
}

void CameraInstruction::TargetInstruction::write(BinaryStream& stream) const {
    stream.writeOptional(mTargetCenterOffset, &Vec3::write);
    stream.writeSignedInt64(mTargetActorId);
}

Result<> CameraInstruction::TargetInstruction::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(stream.readOptional(mTargetCenterOffset, &Vec3::read));
    return stream.readSignedInt64(mTargetActorId);
}

void CameraInstruction::FovInstruction::write(BinaryStream& stream) const {
    stream.writeFloat(mFieldOfView);
    stream.writeFloat(mEaseTime);
    utils::writeEnumName(stream, mEaseType);
    stream.writeBool(mClear);
}

Result<> CameraInstruction::FovInstruction::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(stream.readFloat(mFieldOfView));
    _SCULK_READ(stream.readFloat(mEaseTime));
    _SCULK_READ(utils::readEnumName(stream, mEaseType));
    return stream.readBool(mClear);
}

void CameraInstruction::SplineInstruction::SplineProgressOption::write(BinaryStream& stream) const {
    stream.writeFloat(mKeyFrameValue);
    stream.writeFloat(mKeyFrameTime);
    utils::writeEnumName(stream, mKeyFrameEasingFunc);
}

Result<> CameraInstruction::SplineInstruction::SplineProgressOption::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(stream.readFloat(mKeyFrameValue));
    _SCULK_READ(stream.readFloat(mKeyFrameTime));
    return utils::readEnumName(stream, mKeyFrameEasingFunc);
}

void CameraInstruction::SplineInstruction::RotationOption::write(BinaryStream& stream) const {
    mKeyFrameValues.write(stream);
    stream.writeFloat(mKeyFrameTimes);
    utils::writeEnumName(stream, mKeyFrameEasingFunc);
}

Result<> CameraInstruction::SplineInstruction::RotationOption::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(mKeyFrameValues.read(stream));
    _SCULK_READ(stream.readFloat(mKeyFrameTimes));
    return utils::readEnumName(stream, mKeyFrameEasingFunc);
}

void CameraInstruction::SplineInstruction::write(BinaryStream& stream) const {
    stream.writeFloat(mTotalTime);
    stream.writeEnum(mType, &BinaryStream::writeByte);
    stream.writeArray(mCurve, &Vec3::write);
    stream.writeArray(mProgressKeyFrames, &SplineProgressOption::write);
    stream.writeArray(mRotationOptions, &RotationOption::write);
    stream.writeString(mSplineIdentifier);
    stream.writeBool(mLoadFromJson);
}

Result<> CameraInstruction::SplineInstruction::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(stream.readFloat(mTotalTime));
    _SCULK_READ(stream.readEnum(mType, &ReadOnlyBinaryStream::readByte));
    _SCULK_READ(stream.readArray(mCurve, &Vec3::read));
    _SCULK_READ(stream.readArray(mProgressKeyFrames, &SplineProgressOption::read));
    _SCULK_READ(stream.readArray(mRotationOptions, &RotationOption::read));
    _SCULK_READ(stream.readString(mSplineIdentifier));
    return stream.readBool(mLoadFromJson);
}

void CameraInstruction::AttachToEntityInstruction::write(BinaryStream& stream) const {
    stream.writeSignedInt64(mActorUniqueId);
}

Result<> CameraInstruction::AttachToEntityInstruction::read(ReadOnlyBinaryStream& stream) {
    return stream.readSignedInt64(mActorUniqueId);
}

void CameraInstruction::write(BinaryStream& stream) const {
    stream.writeOptional(mSet, &SetInstruction::write);
    stream.writeOptional(mClear, &BinaryStream::writeBool);
    stream.writeOptional(mFade, &FadeInstruction::write);
    stream.writeOptional(mTarget, &TargetInstruction::write);
    stream.writeOptional(mRemoveTarget, &BinaryStream::writeBool);
    stream.writeOptional(mFieldOfView, &FovInstruction::write);
    stream.writeOptional(mSpline, &SplineInstruction::write);
    stream.writeOptional(mAttachToEntity, &AttachToEntityInstruction::write);
    stream.writeOptional(mDetachFromEntity, &BinaryStream::writeBool);
}

Result<> CameraInstruction::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(stream.readOptional(mSet, &SetInstruction::read));
    _SCULK_READ(stream.readOptional(mClear, &ReadOnlyBinaryStream::readBool));
    _SCULK_READ(stream.readOptional(mFade, &FadeInstruction::read));
    _SCULK_READ(stream.readOptional(mTarget, &TargetInstruction::read));
    _SCULK_READ(stream.readOptional(mRemoveTarget, &ReadOnlyBinaryStream::readBool));
    _SCULK_READ(stream.readOptional(mFieldOfView, &FovInstruction::read));
    _SCULK_READ(stream.readOptional(mSpline, &SplineInstruction::read));
    _SCULK_READ(stream.readOptional(mAttachToEntity, &AttachToEntityInstruction::read));
    return stream.readOptional(mDetachFromEntity, &ReadOnlyBinaryStream::readBool);
}

} // namespace sculk::protocol::inline abi_v975
