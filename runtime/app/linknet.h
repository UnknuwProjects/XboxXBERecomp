#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// Link rooms: the game's own System Link mode carried over the server, so up
// to 8 phones on different networks can meet in one session. The server acts
// as a virtual LAN hub - every phone connects out to it, and it forwards the
// game's broadcast and per-player packets inside the room. Each member gets
// a virtual address (10.250.0.<slot>) that the game sees as its LAN address.
// Implemented in xdk/xnet.cpp, where the game's network calls land.
namespace linknet {

// server is one "host" or "host:port" (default port 42425), or several
// of them separated by ';' - the room then settles on the first server
// that answers, and a host whose servers all stay silent falls back to
// hosting the room on the local Wi-Fi itself (the LAN mode below).
// HostRoom picks the room code itself; read it back with RoomCode().
// mods_hash is the host's mod-set fingerprint (app::ModsSetHash),
// listed with the room so players can see a mismatch before joining.
bool HostRoom(const char* server, const char* name, uint32_t mods_hash);
bool JoinRoom(const char* server, const char* code);
// Join a room hosted on this Wi-Fi: host_ip is the hosting phone's
// address from its room announcement, code the room's code.
bool JoinRoomLan(const char* host_ip, const char* code);
void Leave();

bool Active();     // a room is joined (or being joined) right now
bool IsHost();     // we created the active room (known at once, unlike Slot)
bool Rejected();   // the last join was refused: room full or gone
uint8_t Slot();    // our slot 1..8, 0 until the server assigns one
const char* RoomCode();
bool Lan();        // the room runs on this Wi-Fi, not through a server
bool LanHost();    // we are the phone hosting the LAN room

// The port LAN rooms live on: announcements, joins and traffic.
inline constexpr uint16_t kLanPort = 42427;

// Mod share rides the room channel (section 137): payloads starting
// with 'T4MS' are queued for modshare instead of reaching the game.
void SendShare(const uint8_t* data, size_t len, uint8_t dst_slot);
bool PollShare(uint8_t& src_slot, std::vector<uint8_t>& out);

}  // namespace linknet
