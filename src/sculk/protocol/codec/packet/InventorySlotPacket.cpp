// Copyright © 2026 SculkCatalystMC. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

#include "sculk/protocol/codec/packet/InventorySlotPacket.hpp"

namespace sculk::protocol::inline abi_v975 {

MinecraftPacketIds InventorySlotPacket::getId() const noexcept { return MinecraftPacketIds::InventorySlot; }

std::string_view InventorySlotPacket::getName() const noexcept { return "InventorySlotPacket"; }

void InventorySlotPacket::write(BinaryStream& stream) const {
    stream.writeByte(mInventoryId);
    stream.writeUnsignedVarInt(mSlot);
    stream.writeOptional(mFullContainerName, &FullContainerName::write);
    stream.writeOptional(mStorageItem, &NetworkItemStackDescriptor::writeCereal);
    mItem.writeCereal(stream);
}

Result<> InventorySlotPacket::read(ReadOnlyBinaryStream& stream) {
    _SCULK_READ(stream.readByte(mInventoryId));
    _SCULK_READ(stream.readUnsignedVarInt(mSlot));
    _SCULK_READ(stream.readOptional(mFullContainerName, &FullContainerName::read));
    _SCULK_READ(stream.readOptional(mStorageItem, &NetworkItemStackDescriptor::readCereal));
    return mItem.readCereal(stream);
}

} // namespace sculk::protocol::inline abi_v975
