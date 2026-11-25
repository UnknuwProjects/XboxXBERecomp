#pragma once
#include <mutex>

#include "gpu/state.h"

namespace d3d {

gpu::State& State();
std::recursive_mutex& Lock();

// interpret a finished run of the library's own pushbuffer (guest addresses):
// the method stream the D3D library builds for its internal clients, which no
// device export ever drains in this model
void DrainPush(uint32_t from, uint32_t to);

// the library pushbuffer's segment, learned from its allocator (section 226)
void NotePushAlloc(uint32_t cur, uint32_t end);
// drain whatever the library wrote this frame; called from the Swap export
void DrainLibPushFrame();

}  // namespace d3d
