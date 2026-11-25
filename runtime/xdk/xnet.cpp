// System link on host Winsock. The game reaches the network only through the XNet winsock thunks, replaced
// here. The title's XNet object stays null, so the XNet calls not replaced (Live QoS and the like) fail with
// WSANOTINITIALISED on their own, and the XOnline calls with XONLINE_E_NOT_INITIALIZED.
// Addresses: an XNADDR's ina is the peer's real IPv4, so secure addresses map to IPs one to one.
// With --instance N the game binds 127.0.0.N and a broadcast goes to the other loopback instances.
// Join IP (a host past the LAN): the system link search's broadcasts also go to that address, and the host's
// broadcasts (a LAN discovery may answer every search with one, to 255.255.255.255) go to the public addresses
// that have reached it. With one peer (co-op) a LAN address in an XNADDR, which only means something on its
// owner's LAN, stands for the peer's public one: the join address on the client, the address its packets come
// from on the host. Ports a NAT rewrote are answered on the port the peer's packets came from.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <map>
#include <queue>
#include <random>
#include <thread>

#include "app/app.h"
#include "app/linknet.h"
#include "xdk/hle.h"

using kernel::HostPtr;
using kernel::R32;
using kernel::W32;

namespace {

// XNADDR: ina, inaOnline, wPortOnline, abEnet[6], abOnline[20]
constexpr uint32_t kXnAddrSize = 0x24;
constexpr uint32_t kXnAddrEnet = 0x0A;
// WSAOVERLAPPED: Internal, InternalHigh, Offset, OffsetHigh, hEvent
constexpr uint32_t kOvlStatus = 0x00;
constexpr uint32_t kOvlBytes = 0x04;
constexpr uint32_t kOvlEvent = 0x10;
constexpr uint32_t kOvlPending = 0x103;
// XNDNS: iStatus, cina, aina[8]
constexpr uint32_t kXnDnsSize = 0x28;
// fd_set: fd_count, fd_array[64]
constexpr uint32_t kFdSetMax = 64;

constexpr uint32_t kSocketError = 0xFFFFFFFF;
constexpr uint32_t kLinkUp = 0x01 | 0x02 | 0x08;          // active, 100 Mbps, full duplex
constexpr uint32_t kXnAddrEthernet = 0x02 | 0x04;         // ethernet, static address
constexpr DWORD kUdpConnReset = 0x9800000C;  // SIO_UDP_CONNRESET: off, or a send to a closed port fails the next recv
constexpr int kLoopbackInstances = 8;

struct Socket {
    SOCKET s = INVALID_SOCKET;
    bool udp = false;
    bool nonblocking = false;  // the guest's FIONBIO; the host socket is always nonblocking
    uint16_t port = 0;         // bound, network order
};

struct Span {
    uint32_t ptr, len;
};

// the byte count and flags pointers are only written when the call completes at once, as in Winsock:
// a title may pass its flags on the stack
struct PendingRecv {
    uint32_t sock, ovl, from, fromlen;
    std::vector<Span> spans;  // copied: the title's WSABUF array may live on its stack
};

std::mutex g_lock;
std::unordered_map<uint32_t, Socket> g_sockets;
uint32_t g_next_socket = 0x100;
std::vector<PendingRecv> g_pending;

std::once_flag g_init;
int g_instance = 0;
uint32_t g_local = 0;  // network order
std::array<uint8_t, 8> g_kid{};
std::unordered_map<uint32_t, std::array<uint8_t, kXnAddrSize>> g_peers;

thread_local uint32_t t_error = 0;

std::atomic<uint32_t> g_remote{0};  // the last public address a packet came from
std::mutex g_nat_lock;
std::unordered_map<uint64_t, uint16_t> g_nat;  // (peer address, our port) -> the port its packets come from
std::vector<uint32_t> g_public;                // public addresses packets came from, the latest last
constexpr size_t kMaxPublic = 8;

// ---- link rooms: the game's System Link carried over the server ----
// Members hold virtual LAN addresses 10.250.0.<slot> (in this file's address
// layout the first octet is the low byte, so the slot is the high byte). The
// server is a virtual hub: broadcasts and per-player packets are wrapped and
// forwarded inside the room, and unwrapped packets are served to the guest
// as if they arrived on its own LAN sockets.
constexpr uint32_t kLinkBase = 10u | (250u << 8);
uint32_t LinkIp(uint8_t slot) { return kLinkBase | (uint32_t(slot) << 24); }
bool LinkAddr(uint32_t a) { return (a & 0xFFFFFFu) == kLinkBase && (a >> 24) >= 1 && (a >> 24) <= 8; }

struct LinkDatagram {
    uint32_t src_ip = 0;    // the sender's virtual address
    uint16_t src_port = 0;  // network order
    std::vector<uint8_t> data;
};

std::mutex g_link_lock;
bool g_link_on = false;
bool g_link_host = false;
bool g_link_rejected = false;
uint8_t g_link_slot = 0;
char g_link_code[9] = {};
char g_link_name[25] = {};
uint32_t g_link_mods_hash = 0;
sockaddr_in g_link_server{};
SOCKET g_link_sock = INVALID_SOCKET;
std::thread g_link_thread;
std::atomic<bool> g_link_run{false};
std::map<uint16_t, std::queue<LinkDatagram>> g_link_inbox;  // by destination port, network order
std::queue<std::pair<uint8_t, std::vector<uint8_t>>> g_link_share;  // mod-share payloads, by sender slot
std::vector<sockaddr_in> g_link_servers;  // every anchor the room tries, in order
size_t g_link_server_idx = 0;
std::chrono::steady_clock::time_point g_link_anchor_at{};
bool g_link_lan = false;       // the room's anchor is a phone on this Wi-Fi
bool g_link_lan_host = false;  // that phone is us: we serve the room ourselves
struct LanMember {
    sockaddr_in addr{};
    std::chrono::steady_clock::time_point last{};
};
std::map<uint8_t, LanMember> g_link_members;  // the LAN host's serve table
std::chrono::steady_clock::time_point g_link_announce_at{};

// the address the game should believe is ours right now
uint32_t LinkOwnIp() {
    std::lock_guard<std::mutex> lock(g_link_lock);
    return g_link_on && g_link_slot ? LinkIp(g_link_slot) : g_local;
}

bool LinkInboxRecv(uint32_t sock, const std::vector<Span>& spans, uint32_t from, uint32_t fromlen, int& out);
bool LinkTrySend(uint32_t sock, const uint8_t* data, int len, const sockaddr_in& to);

std::string Ip(uint32_t a) {
    char s[32];
    std::snprintf(s, sizeof(s), "%u.%u.%u.%u", a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, a >> 24);
    return s;
}
std::string Addr(const sockaddr_in& a) { return Ip(a.sin_addr.s_addr) + ":" + std::to_string(ntohs(a.sin_port)); }

bool Private(uint32_t a) {
    uint8_t b0 = a & 0xFF, b1 = (a >> 8) & 0xFF;
    return b0 == 10 || b0 == 127 || (b0 == 172 && (b1 & 0xF0) == 16) || (b0 == 192 && b1 == 168) ||
           (b0 == 169 && b1 == 254);
}

uint64_t NatKey(uint32_t address, uint16_t port) { return uint64_t(address) << 16 | port; }

// the F10 join address, resolved when it changes; 0 for none
uint32_t JoinAddress() {
    static std::mutex m;
    static std::string last;
    static uint32_t address = 0;
    std::string text;
    {
        std::lock_guard<std::recursive_mutex> ui(app::UiLock());
        text = app::Get().join_ip;
    }
    text.erase(0, text.find_first_not_of(" \t"));
    text.erase(text.find_last_not_of(" \t") + 1);
    std::lock_guard<std::mutex> lock(m);
    if (text == last) return address;
    last = text;
    address = 0;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    if (!text.empty() && getaddrinfo(text.c_str(), nullptr, &hints, &res) == 0) {
        address = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(res);
    }
    if (!text.empty()) LOGI("xnet: join %s -> %s", text.c_str(), address ? Ip(address).c_str() : "not found");
    return address;
}

uint32_t PrimaryAddress() {
    uint32_t addr = htonl(INADDR_LOOPBACK);
    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(53);
    to.sin_addr.s_addr = htonl(0x08080808);  // no packet is sent: connect only picks the route
    sockaddr_in me{};
    int len = sizeof(me);
    if (s != INVALID_SOCKET && ::connect(s, reinterpret_cast<sockaddr*>(&to), sizeof(to)) == 0 &&
        ::getsockname(s, reinterpret_cast<sockaddr*>(&me), &len) == 0 && me.sin_addr.s_addr)
        addr = me.sin_addr.s_addr;
    if (s != INVALID_SOCKET) ::closesocket(s);
    return addr;
}

void Pump();

void Init() {
    std::call_once(g_init, [] {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        g_instance = app::Instance();
        g_local = g_instance ? htonl(0x7F000000u | uint32_t(g_instance)) : PrimaryAddress();
        LOGI("xnet: %s address %s", g_instance ? "loopback instance" : "LAN", Ip(g_local).c_str());
        std::thread(Pump).detach();
    });
}

uint32_t Fail(int err) {
    t_error = uint32_t(err);
    return kSocketError;
}
int HostError() {
    int e = WSAGetLastError();
    return e == WSAECONNRESET ? WSAEWOULDBLOCK : e;  // a port unreachable reply from an earlier send
}

Socket Find(uint32_t sock) {
    std::lock_guard<std::mutex> lock(g_lock);
    auto it = g_sockets.find(sock);
    return it == g_sockets.end() ? Socket{} : it->second;
}

sockaddr_in GuestAddr(uint32_t va) {
    sockaddr_in a{};
    std::memcpy(&a, HostPtr(va), sizeof(a));
    return a;
}

void Signal(uint32_t event) {
    if (!event) return;
    if (auto o = kernel::FromHandle(event)) kernel::SetEvent(*o);
}

bool Wait(SOCKET s, bool write, int ms) {
    fd_set f;
    FD_ZERO(&f);
    FD_SET(s, &f);
    timeval tv{ms / 1000, (ms % 1000) * 1000};
    // POSIX select examines only fds below nfds; Winsock ignores the
    // argument, which is how a 0 crept in here and in the two call
    // sites below. With 0 the call is a plain sleep that never reports
    // a ready socket (section 144).
    return ::select(int(s) + 1, write ? nullptr : &f, write ? &f : nullptr, nullptr, &tv) > 0;
}

std::vector<Span> Spans(uint32_t bufs, uint32_t count) {
    std::vector<Span> v;
    for (uint32_t i = 0; i < count; i++) v.push_back({R32(bufs + 8 * i + 4), R32(bufs + 8 * i)});
    return v;
}

// one datagram into guest buffers: bytes, or -1 with err.
// Locking contract: callers hold g_lock (TryComplete states it too);
// nothing in here or below may take g_lock again (section 149).
int Recv(uint32_t sock, SOCKET s, const std::vector<Span>& spans, uint32_t from, uint32_t fromlen, int& err) {
    {
        int done = 0;
        if (LinkInboxRecv(sock, spans, from, fromlen, done)) return done;
    }
    thread_local std::vector<uint8_t> buf(65536);
    sockaddr_in src{};
    int sl = sizeof(src);
    int n = ::recvfrom(s, reinterpret_cast<char*>(buf.data()), int(buf.size()), 0, reinterpret_cast<sockaddr*>(&src), &sl);
    if (n < 0) {
        err = HostError();
        if (err != WSAEWOULDBLOCK) LOG_FIRST(20, "xnet: recv %X failed (%d)", sock, err);
        return -1;
    }
    LOG_FIRST(80, "xnet: recv %X <- %s len %d", sock, Addr(src).c_str(), n);
    int done = 0;
    for (const Span& sp : spans) {
        int c = std::min<int>(n - done, int(sp.len));
        if (c <= 0) break;
        std::memcpy(HostPtr(sp.ptr), buf.data() + done, size_t(c));
        done += c;
    }
    if (done < n) LOG_FIRST(10, "xnet: %d byte datagram cut to %d", n, done);
    uint32_t peer = src.sin_addr.s_addr;
    if (peer != g_local && !Private(peer)) {
        if (g_remote.exchange(peer) != peer) LOGI("xnet: peer %s", Addr(src).c_str());
        auto it = g_sockets.find(sock);
        std::lock_guard<std::mutex> lock(g_nat_lock);
        if (it != g_sockets.end() && it->second.port) g_nat[NatKey(peer, it->second.port)] = src.sin_port;
        std::erase(g_public, peer);
        g_public.push_back(peer);
        if (g_public.size() > kMaxPublic) g_public.erase(g_public.begin());
    }
    if (from) std::memcpy(HostPtr(from), &src, sizeof(src));
    if (fromlen) W32(fromlen, sizeof(src));
    return done;
}

// a broadcast destination: the all-ones address, or a directed subnet
// broadcast (a private address whose last octet is all ones - what a game
// computes from its own address and a netmask). Discovery packets go to
// one of these; the join-target fan-out below must fire for both, or a
// game that uses the directed form never gets its extra unicast copies.
bool BroadcastDest(uint32_t a) {
    return a == INADDR_BROADCAST || (Private(a) && (a >> 24) == 0xFF);
}

int SendOnce(SOCKET s, const uint8_t* data, int len, const sockaddr_in* to) {
    if (!to) return ::send(s, reinterpret_cast<const char*>(data), len, 0);
    sockaddr_in d = *to;
    if (BroadcastDest(d.sin_addr.s_addr)) {
        std::vector<sockaddr_in> also;
        if (uint32_t join = JoinAddress()) {
            also.push_back(d);
            also.back().sin_addr.s_addr = join;
        }
        {
            std::lock_guard<std::mutex> lock(g_nat_lock);
            for (uint32_t peer : g_public) {
                also.push_back(d);
                also.back().sin_addr.s_addr = peer;
                if (auto it = g_nat.find(NatKey(peer, d.sin_port)); it != g_nat.end()) also.back().sin_port = it->second;
            }
        }
        for (const sockaddr_in& a : also)
            ::sendto(s, reinterpret_cast<const char*>(data), len, 0, reinterpret_cast<const sockaddr*>(&a), sizeof(a));
    } else {
        std::lock_guard<std::mutex> lock(g_nat_lock);
        auto it = g_nat.find(NatKey(d.sin_addr.s_addr, d.sin_port));
        if (it != g_nat.end()) d.sin_port = it->second;
    }
    if (g_instance && d.sin_addr.s_addr == INADDR_BROADCAST) {
        for (int i = 1; i <= kLoopbackInstances; i++) {
            if (i == g_instance) continue;
            d.sin_addr.s_addr = htonl(0x7F000000u | uint32_t(i));
            ::sendto(s, reinterpret_cast<const char*>(data), len, 0, reinterpret_cast<sockaddr*>(&d), sizeof(d));
        }
        return len;
    }
    return ::sendto(s, reinterpret_cast<const char*>(data), len, 0, reinterpret_cast<const sockaddr*>(&d), sizeof(d));
}

int Send(uint32_t sock, SOCKET s, const uint8_t* data, int len, const sockaddr_in* to) {
    // session tracing (section 84): bounded, so a multiplayer attempt's log
    // shows the game's whole flow - what it sends where, what comes back
    if (to) LOG_FIRST(80, "xnet: send %X -> %s len %d", sock, Addr(*to).c_str(), len);
    else LOG_FIRST(10, "xnet: send %X (connected) len %d", sock, len);
    if (to && LinkTrySend(sock, data, len, *to)) return len;
    int n = SendOnce(s, data, len, to);
    if (n < 0) LOG_FIRST(20, "xnet: send %X failed (%d)", sock, WSAGetLastError());
    return n;
}

// serve one queued link-room datagram for this socket's bound port, if any.
// Called only from Recv, which every caller runs with g_lock held - so the
// socket lookup here must NOT take g_lock again: it is a plain mutex, and
// re-locking it deadlocked the calling thread on the spot. That was the
// System Link freeze (section 149): the first receive after the discovery
// broadcast - direct, overlapped, or via the pump - hung forever holding
// g_lock, which then stalled every other xnet call behind it.
bool LinkInboxRecv(uint32_t sock, const std::vector<Span>& spans, uint32_t from, uint32_t fromlen, int& out) {
    uint16_t port = 0;
    if (auto it = g_sockets.find(sock); it != g_sockets.end()) port = it->second.port;
    if (!port) return false;
    LinkDatagram d;
    {
        std::lock_guard<std::mutex> lock(g_link_lock);
        auto q = g_link_inbox.find(port);
        if (q == g_link_inbox.end() || q->second.empty()) return false;
        d = std::move(q->second.front());
        q->second.pop();
    }
    int n = int(d.data.size());
    int done = 0;
    for (const Span& sp : spans) {
        int c = std::min<int>(n - done, int(sp.len));
        if (c <= 0) break;
        std::memcpy(HostPtr(sp.ptr), d.data.data() + done, size_t(c));
        done += c;
    }
    LOG_FIRST(80, "xnet: recv %X <- link %s len %d", sock, Ip(d.src_ip).c_str(), n);
    if (from) {
        sockaddr_in src{};
        src.sin_family = AF_INET;
        src.sin_addr.s_addr = d.src_ip;
        src.sin_port = d.src_port;
        std::memcpy(HostPtr(from), &src, sizeof(src));
    }
    if (fromlen) W32(fromlen, sizeof(sockaddr_in));
    out = done;
    return true;
}

// wrap a packet for the server. Broadcasts are also sent on the real LAN by
// the caller (returns false); unicast to a room member is fully handled here.
bool LinkTrySend(uint32_t sock, const uint8_t* data, int len, const sockaddr_in& to) {
    uint32_t dst = to.sin_addr.s_addr;
    bool bcast = BroadcastDest(dst);
    if (!bcast && !LinkAddr(dst)) return false;
    SOCKET ls;
    sockaddr_in server;
    uint8_t slot;
    char code[9];
    bool lan_host = false;
    std::map<uint8_t, LanMember> members;
    {
        std::lock_guard<std::mutex> lock(g_link_lock);
        if (!g_link_on || !g_link_slot || g_link_sock == INVALID_SOCKET) return false;
        ls = g_link_sock;
        server = g_link_server;
        slot = g_link_slot;
        std::memcpy(code, g_link_code, 9);
        lan_host = g_link_lan_host;
        if (lan_host) members = g_link_members;
    }
    uint16_t src_port = 0;
    {
        std::lock_guard<std::mutex> lock(g_lock);
        auto it = g_sockets.find(sock);
        if (it != g_sockets.end()) src_port = it->second.port;
    }
    if (!src_port) src_port = to.sin_port;  // session traffic answers on the port it was addressed on
    std::vector<uint8_t> p(18 + size_t(len));
    std::memcpy(p.data(), "T4SL", 4);
    std::memcpy(p.data() + 4, code, 8);
    p[12] = slot;
    p[13] = bcast ? 0 : uint8_t(dst >> 24);
    std::memcpy(p.data() + 14, &src_port, 2);
    std::memcpy(p.data() + 16, &to.sin_port, 2);
    if (len) std::memcpy(p.data() + 18, data, size_t(len));
    if (lan_host) {
        // we are the room's hub: members get the packet directly,
        // a broadcast goes to every member, our own slot drops it
        if (bcast) {
            for (auto& [s, m] : members)
                ::sendto(ls, reinterpret_cast<const char*>(p.data()), int(p.size()), 0,
                         reinterpret_cast<const sockaddr*>(&m.addr), sizeof(m.addr));
        } else {
            const uint8_t d = uint8_t(dst >> 24);
            if (d != slot) {
                auto it = members.find(d);
                if (it != members.end())
                    ::sendto(ls, reinterpret_cast<const char*>(p.data()), int(p.size()), 0,
                             reinterpret_cast<const sockaddr*>(&it->second.addr),
                             sizeof(it->second.addr));
            }
        }
        return true;
    }
    ::sendto(ls, reinterpret_cast<const char*>(p.data()), int(p.size()), 0,
             reinterpret_cast<const sockaddr*>(&server), sizeof(server));
    // inside a link room the virtual LAN is the only LAN
    // (section 230): a broadcast wrapped for the server must
    // not also leave on the real one, or a local session can
    // be discovered from inside the room
    return true;
}

void LinkSendRegister() {
    uint8_t p[15 + 24 + 4];
    char code[9], name[25];
    bool host;
    uint32_t mods_hash;
    SOCKET ls;
    sockaddr_in server;
    {
        std::lock_guard<std::mutex> lock(g_link_lock);
        host = g_link_host;
        mods_hash = g_link_mods_hash;
        ls = g_link_sock;
        server = g_link_server;
        std::memcpy(code, g_link_code, 9);
        std::memcpy(name, g_link_name, 25);
    }
    if (ls == INVALID_SOCKET) return;
    std::memcpy(p, "T4R1", 4);
    p[4] = host ? 0 : 1;
    std::memcpy(p + 5, code, 8);
    size_t nl = std::strlen(name);
    p[13] = host ? 0x03 : 0x02;  // link bit; the host's room is public too, so it lists
    p[14] = uint8_t(nl);
    std::memcpy(p + 15, name, nl);
    size_t len = 15 + nl;
    if (host) {  // the mod-set hash rides after the name (section 137)
        p[len + 0] = uint8_t(mods_hash >> 24);
        p[len + 1] = uint8_t(mods_hash >> 16);
        p[len + 2] = uint8_t(mods_hash >> 8);
        p[len + 3] = uint8_t(mods_hash);
        len += 4;
    }
    ::sendto(ls, reinterpret_cast<const char*>(p), int(len), 0,
             reinterpret_cast<const sockaddr*>(&server), sizeof(server));
}

bool SameAddr(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

// The LAN host's half of the room (section 239): when no server
// answers, the hosting phone takes the server's own job over - it
// hands out slots, keeps the roster and forwards traffic, with the
// same packet shapes and the same 15 seconds of silence the server
// allows before a member is forgotten.
void LinkLanAnnounce() {
    SOCKET ls;
    char code[9], name[25];
    uint32_t mods;
    int members;
    {
        std::lock_guard<std::mutex> lock(g_link_lock);
        if (!g_link_lan_host || g_link_sock == INVALID_SOCKET) return;
        ls = g_link_sock;
        std::memcpy(code, g_link_code, 9);
        std::memcpy(name, g_link_name, 25);
        mods = g_link_mods_hash;
        members = 1 + int(g_link_members.size());
    }
    uint8_t p[19 + 24];
    std::memcpy(p, "T4LB", 4);
    std::memcpy(p + 4, code, 8);
    p[12] = 1;  // kind: link room
    p[13] = uint8_t(members);
    p[14] = uint8_t(mods >> 24);
    p[15] = uint8_t(mods >> 16);
    p[16] = uint8_t(mods >> 8);
    p[17] = uint8_t(mods);
    const size_t nl = std::strlen(name);
    p[18] = uint8_t(nl);
    std::memcpy(p + 19, name, nl);
    sockaddr_in bcast{};
    bcast.sin_family = AF_INET;
    bcast.sin_port = htons(linknet::kLanPort);
    bcast.sin_addr.s_addr = INADDR_BROADCAST;
    ::sendto(ls, reinterpret_cast<const char*>(p), int(19 + nl), 0,
             reinterpret_cast<const sockaddr*>(&bcast), sizeof(bcast));
}

void LinkLanServeRegister(const uint8_t* buf, const sockaddr_in& src) {
    if (buf[4] != 1) return;  // only joiners register with the host
    SOCKET ls = INVALID_SOCKET;
    uint8_t slot = 0;
    bool full = false, fresh = false;
    char code[9] = {};
    {
        std::lock_guard<std::mutex> lock(g_link_lock);
        if (!g_link_lan_host || g_link_sock == INVALID_SOCKET) return;
        if (std::memcmp(buf + 5, g_link_code, 8) != 0) return;
        ls = g_link_sock;
        std::memcpy(code, g_link_code, 9);
        const auto now = std::chrono::steady_clock::now();
        for (auto& [s, m] : g_link_members)
            if (SameAddr(m.addr, src)) {
                slot = s;
                m.last = now;
                break;
            }
        if (!slot) {
            for (uint8_t s = 2; s <= 8 && !slot; s++)
                if (!g_link_members.count(s)) slot = s;
            if (slot) {
                g_link_members[slot] = LanMember{src, now};
                fresh = true;
            } else {
                full = true;
            }
        }
    }
    if (full) {
        uint8_t p[12];
        std::memcpy(p, "T4LX", 4);
        std::memcpy(p + 4, code, 8);
        ::sendto(ls, reinterpret_cast<const char*>(p), 12, 0,
                 reinterpret_cast<const sockaddr*>(&src), sizeof(src));
        return;
    }
    if (!slot) return;
    uint8_t p[13];
    std::memcpy(p, "T4LA", 4);
    std::memcpy(p + 4, code, 8);
    p[12] = slot;
    ::sendto(ls, reinterpret_cast<const char*>(p), 13, 0,
             reinterpret_cast<const sockaddr*>(&src), sizeof(src));
    if (fresh) LOGI("xnet: link room %s, slot %u joined over the Wi-Fi", code, slot);
}

void LinkLanServeForward(const uint8_t* buf, int n, const sockaddr_in& src) {
    const uint8_t src_slot = buf[12], dst = buf[13];
    SOCKET ls = INVALID_SOCKET;
    std::vector<sockaddr_in> targets;
    {
        std::lock_guard<std::mutex> lock(g_link_lock);
        if (!g_link_lan_host || g_link_sock == INVALID_SOCKET) return;
        if (std::memcmp(buf + 4, g_link_code, 8) != 0) return;
        auto it = g_link_members.find(src_slot);
        if (it == g_link_members.end() || !SameAddr(it->second.addr, src)) return;
        it->second.last = std::chrono::steady_clock::now();
        ls = g_link_sock;
        if (dst == 0) {
            for (auto& [s, m] : g_link_members)
                if (s != src_slot) targets.push_back(m.addr);
        } else {
            auto d = g_link_members.find(dst);
            if (d != g_link_members.end()) targets.push_back(d->second.addr);
        }
    }
    for (auto& t : targets)
        ::sendto(ls, reinterpret_cast<const char*>(buf), n, 0,
                 reinterpret_cast<const sockaddr*>(&t), sizeof(t));
}

void LinkLanRefresh(const uint8_t* buf, const sockaddr_in& src) {
    std::lock_guard<std::mutex> lock(g_link_lock);
    if (!g_link_lan_host) return;
    if (std::memcmp(buf + 4, g_link_code, 8) != 0) return;
    for (auto& [s, m] : g_link_members)
        if (SameAddr(m.addr, src)) {
            m.last = std::chrono::steady_clock::now();
            return;
        }
}

void LinkLanExpire(std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(g_link_lock);
    for (auto it = g_link_members.begin(); it != g_link_members.end();) {
        if (now - it->second.last > std::chrono::seconds(15)) {
            LOGI("xnet: link room %s, slot %u went quiet and is out", g_link_code, it->first);
            it = g_link_members.erase(it);
        } else {
            ++it;
        }
    }
}

// The room moves onto this Wi-Fi: a fresh socket bound to the LAN
// port (the old one was a client socket to a server), slot 1 is
// ours by definition, and the announcements start the roster.
void LinkEnterLanHost() {
    SOCKET ns = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ns == INVALID_SOCKET) return;
    int yes = 1;
    ::setsockopt(ns, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    ::setsockopt(ns, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
    sockaddr_in any{};
    any.sin_family = AF_INET;
    any.sin_addr.s_addr = INADDR_ANY;
    any.sin_port = htons(linknet::kLanPort);
    if (::bind(ns, reinterpret_cast<const sockaddr*>(&any), sizeof(any)) != 0) {
        ::closesocket(ns);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(g_link_lock);
        if (g_link_sock != INVALID_SOCKET) ::closesocket(g_link_sock);
        g_link_sock = ns;
        g_link_lan = true;
        g_link_lan_host = true;
        g_link_slot = 1;
        g_link_members.clear();
        g_link_announce_at = std::chrono::steady_clock::now() - std::chrono::seconds(10);
    }
    LOGI("xnet: link room %s is now hosted on this Wi-Fi", g_link_code);
}

void LinkWorker() {
    auto last_reg = std::chrono::steady_clock::now() - std::chrono::seconds(10);
    std::vector<uint8_t> buf(65536);
    while (g_link_run) {
        uint8_t slot;
        SOCKET ls;
        bool lan, lan_host, is_host;
        {
            std::lock_guard<std::mutex> lock(g_link_lock);
            slot = g_link_slot;
            ls = g_link_sock;
            lan = g_link_lan;
            lan_host = g_link_lan_host;
            is_host = g_link_host;
        }
        if (ls == INVALID_SOCKET) break;
        auto now = std::chrono::steady_clock::now();
        if (!slot && !lan) {
            // no assignment yet: walk the server list, three seconds
            // each, and settle on the last. A host that runs out of
            // servers takes the room onto this Wi-Fi instead - the
            // players next to him are never locked out by a dead
            // server (section 239).
            bool rotate = false, go_lan = false;
            {
                std::lock_guard<std::mutex> lock(g_link_lock);
                if (now - g_link_anchor_at >= std::chrono::seconds(3)) {
                    if (g_link_server_idx + 1 < g_link_servers.size()) {
                        g_link_server_idx++;
                        g_link_server = g_link_servers[g_link_server_idx];
                        g_link_anchor_at = now;
                        rotate = true;
                    } else if (is_host) {
                        go_lan = true;
                    } else {
                        g_link_anchor_at = now;  // a joiner keeps waiting on the last server
                    }
                }
            }
            if (rotate) last_reg = now - std::chrono::seconds(10);
            if (go_lan) {
                LinkEnterLanHost();
                continue;
            }
        }
        if (lan_host) {
            bool due = false;
            {
                std::lock_guard<std::mutex> lock(g_link_lock);
                if (now - g_link_announce_at >= std::chrono::seconds(1)) {
                    g_link_announce_at = now;
                    due = true;
                }
            }
            if (due) {
                LinkLanAnnounce();
                LinkLanExpire(now);
            }
        } else if (now - last_reg >= std::chrono::seconds(slot ? 5 : 1)) {
            LinkSendRegister();
            last_reg = now;
        }
        fd_set set;
        FD_ZERO(&set);
        FD_SET(ls, &set);
        timeval tv{0, 200000};
        if (::select(int(ls) + 1, &set, nullptr, nullptr, &tv) <= 0) continue;
        sockaddr_in src{};
        int sl = sizeof(src);
        int n = ::recvfrom(ls, reinterpret_cast<char*>(buf.data()), int(buf.size()), 0,
                           reinterpret_cast<sockaddr*>(&src), &sl);
        if (n < 0) continue;
        if (lan_host) {
            // the LAN host's serve half: joins, keepalives and
            // traffic to forward. Traffic addressed to slot 1 falls
            // through to the normal delivery below.
            if (n >= 15 && std::memcmp(buf.data(), "T4R1", 4) == 0) {
                LinkLanServeRegister(buf.data(), src);
                continue;
            }
            if (n >= 12 && std::memcmp(buf.data(), "T4K1", 4) == 0) {
                LinkLanRefresh(buf.data(), src);
                continue;
            }
            if (n > 18 && std::memcmp(buf.data(), "T4SL", 4) == 0 && buf[13] != 1) {
                LinkLanServeForward(buf.data(), n, src);
                continue;
            }
        }
        if (n >= 13 && std::memcmp(buf.data(), "T4LA", 4) == 0) {
            std::lock_guard<std::mutex> lock(g_link_lock);
            if (std::memcmp(buf.data() + 4, g_link_code, 8) == 0 && buf[12] >= 1 && buf[12] <= 8) {
                if (g_link_slot != buf[12])
                    LOGI("xnet: link room %s, we are slot %u (%s)", g_link_code, buf[12],
                         Ip(LinkIp(buf[12])).c_str());
                g_link_slot = buf[12];
            }
        } else if (n >= 12 && std::memcmp(buf.data(), "T4LX", 4) == 0) {
            std::lock_guard<std::mutex> lock(g_link_lock);
            if (std::memcmp(buf.data() + 4, g_link_code, 8) == 0) {
                LOGW("xnet: link room %s refused (full or gone)", g_link_code);
                g_link_rejected = true;
                g_link_on = false;
                g_link_slot = 0;
                g_link_run = false;
            }
        } else if (n > 18 && std::memcmp(buf.data(), "T4SL", 4) == 0) {
            uint8_t src_slot = buf[12];
            uint16_t sport, dport;
            std::memcpy(&sport, buf.data() + 14, 2);
            std::memcpy(&dport, buf.data() + 16, 2);
            if (src_slot < 1 || src_slot > 8) continue;
            std::lock_guard<std::mutex> lock(g_link_lock);
            if (!g_link_on || std::memcmp(buf.data() + 4, g_link_code, 8) != 0) continue;
            if (n > 22 && std::memcmp(buf.data() + 18, "T4MS", 4) == 0) {
                // mod share rides the room channel, not the game
                if (g_link_share.size() < 256)
                    g_link_share.push({src_slot, {buf.begin() + 18, buf.begin() + n}});
                continue;
            }
            auto& q = g_link_inbox[dport];
            if (q.size() < 512)
                q.push({LinkIp(src_slot), sport, {buf.begin() + 18, buf.begin() + n}});
        }
    }
}

bool LinkResolve(const char* server, sockaddr_in& out) {
    std::string text = server ? server : "";
    text.erase(0, text.find_first_not_of(" \t"));
    text.erase(text.find_last_not_of(" \t") + 1);
    if (text.empty()) return false;
    std::string host = text;
    uint16_t port = 42425;
    if (size_t c = text.rfind(':'); c != std::string::npos) {
        host = text.substr(0, c);
        int p = std::atoi(text.c_str() + c + 1);
        if (p > 0 && p < 65536) port = uint16_t(p);
    }
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
    out = *reinterpret_cast<sockaddr_in*>(res->ai_addr);
    freeaddrinfo(res);
    out.sin_port = htons(port);
    return true;
}

void LinkStop() {
    g_link_run = false;
    if (g_link_thread.joinable()) g_link_thread.join();
    std::lock_guard<std::mutex> lock(g_link_lock);
    if (g_link_sock != INVALID_SOCKET) {
        ::closesocket(g_link_sock);
        g_link_sock = INVALID_SOCKET;
    }
    g_link_on = false;
    g_link_slot = 0;
    g_link_rejected = false;
    g_link_code[0] = 0;
    g_link_servers.clear();
    g_link_server_idx = 0;
    g_link_lan = false;
    g_link_lan_host = false;
    g_link_members.clear();
    g_link_inbox.clear();
}

bool LinkStart(const char* server, const char* name, const char* code, bool host,
               uint32_t mods_hash = 0, bool lan = false) {
    // the server argument may carry several addresses separated by
    // ';' (section 239): the worker walks them in order and settles
    // on the first that assigns a slot. A host with no address at
    // all goes straight to the Wi-Fi fallback in the worker.
    std::vector<sockaddr_in> addrs;
    if (server) {
        const std::string all(server);
        for (size_t at = 0;;) {
            const size_t semi = all.find(';', at);
            const std::string one =
                all.substr(at, semi == std::string::npos ? semi : semi - at);
            sockaddr_in a{};
            if (LinkResolve(one.c_str(), a)) addrs.push_back(a);
            if (semi == std::string::npos) break;
            at = semi + 1;
        }
    }
    if (addrs.empty() && (!host || lan)) return false;
    LinkStop();
    SOCKET ls = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ls == INVALID_SOCKET) return false;
    {
        std::lock_guard<std::mutex> lock(g_link_lock);
        g_link_sock = ls;
        g_link_servers = addrs;
        g_link_server_idx = 0;
        g_link_server = addrs.empty() ? sockaddr_in{} : addrs[0];
        g_link_anchor_at = std::chrono::steady_clock::now();
        g_link_lan = lan;
        g_link_lan_host = false;
        g_link_members.clear();
        g_link_host = host;
        g_link_mods_hash = mods_hash;
        g_link_rejected = false;
        g_link_slot = 0;
        std::snprintf(g_link_name, sizeof(g_link_name), "%s", name ? name : "");
        if (host) {
            static const char kAbc[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
            static std::mt19937 rng{std::random_device{}()};
            for (int i = 0; i < 8; i++) g_link_code[i] = kAbc[rng() % 32];
            g_link_code[8] = 0;
        } else {
            std::snprintf(g_link_code, sizeof(g_link_code), "%s", code ? code : "");
        }
        g_link_on = true;
    }
    g_link_run = true;
    g_link_thread = std::thread(LinkWorker);
    LOGI("xnet: link room %s (%s) via %s", g_link_code, host ? "host" : "join", server ? server : "");
    return true;
}

std::vector<uint8_t> Gather(uint32_t bufs, uint32_t count) {
    std::vector<uint8_t> v;
    for (const Span& sp : Spans(bufs, count)) {
        auto p = static_cast<const uint8_t*>(HostPtr(sp.ptr));
        v.insert(v.end(), p, p + sp.len);
    }
    return v;
}

void Complete(uint32_t ovl, uint32_t status, uint32_t bytes) {
    W32(ovl + kOvlBytes, bytes);
    W32(ovl + kOvlStatus, status);
    Signal(R32(ovl + kOvlEvent));
}

// with g_lock held: false while no datagram is waiting
bool TryComplete(PendingRecv& p) {
    auto it = g_sockets.find(p.sock);
    if (it == g_sockets.end()) {
        Complete(p.ovl, WSAENOTSOCK, 0);
        return true;
    }
    int err = 0;
    int n = Recv(p.sock, it->second.s, p.spans, p.from, p.fromlen, err);
    if (n < 0 && err == WSAEWOULDBLOCK) return false;
    Complete(p.ovl, n < 0 ? uint32_t(err) : 0, n < 0 ? 0 : uint32_t(n));
    return true;
}

void Pump() {
    for (;;) {
        fd_set set;
        FD_ZERO(&set);
        int nfds = 0;
        {
            std::lock_guard<std::mutex> lock(g_lock);
            for (auto& p : g_pending) {
                auto it = g_sockets.find(p.sock);
                if (it != g_sockets.end() && set.fd_count < FD_SETSIZE) {
                    FD_SET(it->second.s, &set);
                    nfds = std::max(nfds, int(it->second.s) + 1);
                }
            }
        }
        if (!set.fd_count) {
            Sleep(1);
            continue;
        }
        timeval tv{0, 2000};
        if (::select(nfds, &set, nullptr, nullptr, &tv) <= 0) {
            Sleep(1);
            continue;
        }
        std::lock_guard<std::mutex> lock(g_lock);
        for (size_t i = 0; i < g_pending.size();) {
            auto it = g_sockets.find(g_pending[i].sock);
            bool ready = it == g_sockets.end() || FD_ISSET(it->second.s, &set);
            if (ready && TryComplete(g_pending[i]))
                g_pending.erase(g_pending.begin() + ptrdiff_t(i));
            else
                i++;
        }
    }
}

void OwnXnAddr(uint8_t* x) {
    uint32_t me = LinkOwnIp();  // our virtual address while in a link room
    std::memset(x, 0, kXnAddrSize);
    std::memcpy(x, &me, 4);
    // Microsoft's OUI, then the address's last three bytes
    const uint8_t mac[6] = {0x00, 0x50, 0xF2, uint8_t(me >> 8), uint8_t(me >> 16), uint8_t(me >> 24)};
    std::memcpy(x + kXnAddrEnet, mac, 6);
}

void Random(uint32_t va, uint32_t n) {
    static std::mutex m;
    static std::mt19937 rng{std::random_device{}()};
    std::lock_guard<std::mutex> lock(m);
    auto p = static_cast<uint8_t*>(HostPtr(va));
    for (uint32_t i = 0; i < n; i++) p[i] = uint8_t(rng());
}

}  // namespace

namespace linknet {

bool HostRoom(const char* server, const char* name, uint32_t mods_hash) {
    return LinkStart(server, name, nullptr, true, mods_hash);
}
bool JoinRoom(const char* server, const char* code) { return LinkStart(server, "PLAYER", code, false); }
bool JoinRoomLan(const char* host_ip, const char* code) {
    // the anchor is the hosting phone itself, on the LAN port; the
    // worker registers with it exactly as it would with a server
    const std::string server = std::string(host_ip ? host_ip : "") + ":" +
                               std::to_string(kLanPort);
    return LinkStart(server.c_str(), "PLAYER", code, false, 0, true);
}
bool Lan() {
    std::lock_guard<std::mutex> lock(g_link_lock);
    return g_link_on && g_link_lan;
}
bool LanHost() {
    std::lock_guard<std::mutex> lock(g_link_lock);
    return g_link_on && g_link_lan_host;
}
void Leave() { LinkStop(); }
bool Active() {
    std::lock_guard<std::mutex> lock(g_link_lock);
    return g_link_on;
}
bool IsHost() {
    std::lock_guard<std::mutex> lock(g_link_lock);
    return g_link_on && g_link_host;
}
bool Rejected() {
    std::lock_guard<std::mutex> lock(g_link_lock);
    return g_link_rejected;
}
uint8_t Slot() {
    std::lock_guard<std::mutex> lock(g_link_lock);
    return g_link_slot;
}
const char* RoomCode() {
    static thread_local char buf[9];
    std::lock_guard<std::mutex> lock(g_link_lock);
    std::memcpy(buf, g_link_code, 9);
    return buf;
}

void SendShare(const uint8_t* data, size_t len, uint8_t dst_slot) {
    SOCKET ls;
    sockaddr_in server;
    uint8_t slot;
    char code[9];
    bool lan_host_share = false;
    std::map<uint8_t, LanMember> share_members;
    {
        std::lock_guard<std::mutex> lock(g_link_lock);
        if (!g_link_on || !g_link_slot || g_link_sock == INVALID_SOCKET) return;
        ls = g_link_sock;
        server = g_link_server;
        slot = g_link_slot;
        std::memcpy(code, g_link_code, 9);
        lan_host_share = g_link_lan_host;
        if (lan_host_share) share_members = g_link_members;
    }
    std::vector<uint8_t> p(18 + len);
    std::memcpy(p.data(), "T4SL", 4);
    std::memcpy(p.data() + 4, code, 8);
    p[12] = slot;
    p[13] = dst_slot;
    const uint16_t port = htons(42426);  // a fixed marker port; the game never sees these
    std::memcpy(p.data() + 14, &port, 2);
    std::memcpy(p.data() + 16, &port, 2);
    if (len) std::memcpy(p.data() + 18, data, len);
    if (lan_host_share) {
        // hosted on this Wi-Fi: the member gets it directly
        if (dst_slot == 0) {
            for (auto& [s, m] : share_members)
                ::sendto(ls, reinterpret_cast<const char*>(p.data()), int(p.size()), 0,
                         reinterpret_cast<const sockaddr*>(&m.addr), sizeof(m.addr));
        } else {
            auto it = share_members.find(dst_slot);
            if (it != share_members.end())
                ::sendto(ls, reinterpret_cast<const char*>(p.data()), int(p.size()), 0,
                         reinterpret_cast<const sockaddr*>(&it->second.addr),
                         sizeof(it->second.addr));
        }
        return;
    }
    ::sendto(ls, reinterpret_cast<const char*>(p.data()), int(p.size()), 0,
             reinterpret_cast<const sockaddr*>(&server), sizeof(server));
}

bool PollShare(uint8_t& src_slot, std::vector<uint8_t>& out) {
    std::lock_guard<std::mutex> lock(g_link_lock);
    if (g_link_share.empty()) return false;
    src_slot = g_link_share.front().first;
    out = std::move(g_link_share.front().second);
    g_link_share.pop();
    return true;
}

}  // namespace linknet

namespace xnet {

void CloseSockets() {
    std::lock_guard<std::mutex> lock(g_lock);
    for (auto& [id, socket] : g_sockets) ::closesocket(socket.s);
    g_sockets.clear();
    g_pending.clear();
}

}  // namespace xnet

HLE_STDCALL(XNetStartup, 1) {
    Init();
    return 0;
}
HLE_STDCALL(WSAStartup, 2) {
    Init();
    if (a[1]) {
        std::memset(HostPtr(a[1]), 0, 400);
        W32(a[1], 0x02020202);  // wVersion, wHighVersion
    }
    return 0;
}
HLE_STDCALL(XNetGetEthernetLinkStatus, 0) { return kLinkUp; }
HLE_STDCALL(XOnlineStartup, 1) { return 0; }
HLE_STDCALL(XOnlineCleanup, 0) { return 0; }
HLE_STDCALL(WSAGetLastError, 0) { return t_error; }

HLE_STDCALL(XNetRandom, 2) {
    Random(a[0], a[1]);
    return 0;
}
HLE_STDCALL(XNetCreateKey, 2) {
    Random(a[0], 8);
    Random(a[1], 16);
    kernel::G<uint8_t>(a[0]) &= 0x0F;
    return 0;
}
HLE_STDCALL(XNetRegisterKey, 2) {
    std::lock_guard<std::mutex> lock(g_lock);
    std::memcpy(g_kid.data(), HostPtr(a[0]), 8);
    LOGI("xnet: session key registered");
    return 0;
}
HLE_STDCALL(XNetUnregisterKey, 1) { return 0; }

HLE_STDCALL(XNetGetTitleXnAddr, 1) {
    Init();
    OwnXnAddr(static_cast<uint8_t*>(HostPtr(a[0])));
    return kXnAddrEthernet;
}
HLE_STDCALL(XNetXnAddrToInAddr, 3) {
    uint32_t ina = R32(a[0]);
    if (!ina) return WSAEINVAL;
    if (ina != g_local && Private(ina) && !g_instance && !LinkAddr(ina)) {
        uint32_t join = JoinAddress(), remote = g_remote;
        if (join && !Private(join)) ina = join;
        else if (remote) ina = remote;
    }
    {
        std::lock_guard<std::mutex> lock(g_lock);
        std::memcpy(g_peers[ina].data(), HostPtr(a[0]), kXnAddrSize);
    }
    W32(a[2], ina);
    return 0;
}
HLE_STDCALL(XNetInAddrToXnAddr, 3) {
    uint32_t ina = a[0];
    uint8_t x[kXnAddrSize];
    std::lock_guard<std::mutex> lock(g_lock);
    auto it = g_peers.find(ina);
    if (!ina || ina == g_local || ina == LinkOwnIp()) {
        OwnXnAddr(x);
    } else if (it != g_peers.end()) {
        std::memcpy(x, it->second.data(), kXnAddrSize);
    } else {
        std::memset(x, 0, kXnAddrSize);
        std::memcpy(x, &ina, 4);
    }
    if (a[1]) std::memcpy(HostPtr(a[1]), x, kXnAddrSize);
    if (a[2]) std::memcpy(HostPtr(a[2]), g_kid.data(), 8);
    return 0;
}

HLE_STDCALL(XNetDnsLookup, 3) {
    std::string name = kernel::ReadCString(a[0], 256);
    uint32_t dns = mem::AllocSystem(kXnDnsSize);
    std::memset(HostPtr(dns), 0, kXnDnsSize);
    addrinfo hints{};
    hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    uint32_t count = 0;
    if (getaddrinfo(name.c_str(), nullptr, &hints, &res) == 0) {
        for (addrinfo* r = res; r && count < 8; r = r->ai_next)
            W32(dns + 8 + 4 * count++, reinterpret_cast<sockaddr_in*>(r->ai_addr)->sin_addr.s_addr);
        freeaddrinfo(res);
    }
    W32(dns, count ? 0 : WSAHOST_NOT_FOUND);
    W32(dns + 4, count);
    W32(a[2], dns);
    LOGI("xnet: dns %s -> %u addresses", name.c_str(), count);
    Signal(a[1]);
    return 0;
}
HLE_STDCALL(XNetDnsRelease, 1) {
    if (a[0]) mem::FreeSystem(a[0]);
    return 0;
}

static uint32_t AddSocket(SOCKET s, bool udp) {
    u_long on = 1;
    ::ioctlsocket(s, FIONBIO, &on);
    if (udp) {
        BOOL off = FALSE;
        DWORD ret = 0;
        WSAIoctl(s, kUdpConnReset, &off, sizeof(off), nullptr, 0, &ret, nullptr, nullptr);
    }
    std::lock_guard<std::mutex> lock(g_lock);
    uint32_t id = g_next_socket;
    g_next_socket += 4;
    g_sockets[id] = {s, udp, false, 0};
    return id;
}

HLE_STDCALL(socket, 3) {
    Init();
    uint32_t af = a[0], type = a[1];  // the protocol: UDP, or VDP, which is UDP between two copies of this
    if (af != AF_INET) return Fail(WSAEAFNOSUPPORT);
    bool udp = type == SOCK_DGRAM;
    if (!udp && type != SOCK_STREAM) return Fail(WSAESOCKTNOSUPPORT);
    SOCKET s = ::socket(AF_INET, int(type), udp ? IPPROTO_UDP : IPPROTO_TCP);
    if (s == INVALID_SOCKET) return Fail(HostError());
    uint32_t id = AddSocket(s, udp);
    LOGI("xnet: socket %X %s", id, udp ? "udp" : "tcp");
    return id;
}
HLE_STDCALL(closesocket, 1) {
    std::lock_guard<std::mutex> lock(g_lock);
    auto it = g_sockets.find(a[0]);
    if (it == g_sockets.end()) return Fail(WSAENOTSOCK);
    for (size_t i = 0; i < g_pending.size();) {
        if (g_pending[i].sock == a[0])
            g_pending.erase(g_pending.begin() + ptrdiff_t(i));
        else
            i++;
    }
    ::closesocket(it->second.s);
    g_sockets.erase(it);
    return 0;
}
HLE_STDCALL(shutdown, 2) {
    Socket k = Find(a[0]);
    if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
    return ::shutdown(k.s, int(a[1])) == 0 ? 0 : Fail(HostError());
}
HLE_STDCALL(ioctlsocket, 3) {
    std::lock_guard<std::mutex> lock(g_lock);
    auto it = g_sockets.find(a[0]);
    if (it == g_sockets.end()) return Fail(WSAENOTSOCK);
    if (a[1] == uint32_t(FIONBIO)) {
        it->second.nonblocking = R32(a[2]) != 0;
        return 0;
    }
    u_long v = R32(a[2]);
    if (::ioctlsocket(it->second.s, long(a[1]), &v) != 0) return Fail(HostError());
    W32(a[2], uint32_t(v));
    return 0;
}
HLE_STDCALL(setsockopt, 5) {
    Socket k = Find(a[0]);
    if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
    if (::setsockopt(k.s, int(a[1]), int(a[2]), static_cast<const char*>(HostPtr(a[3])), int(a[4])) == 0) return 0;
    LOG_FIRST(10, "xnet: setsockopt %X level %X option %X ignored (%d)", a[0], a[1], a[2], WSAGetLastError());
    return 0;
}
HLE_STDCALL(getsockopt, 5) {
    Socket k = Find(a[0]);
    if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
    int len = int(R32(a[4]));
    if (::getsockopt(k.s, int(a[1]), int(a[2]), static_cast<char*>(HostPtr(a[3])), &len) != 0) return Fail(WSAGetLastError());
    W32(a[4], uint32_t(len));
    return 0;
}
HLE_STDCALL(getsockname, 3) {
    Socket k = Find(a[0]);
    if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
    sockaddr_in me{};
    int len = sizeof(me);
    if (::getsockname(k.s, reinterpret_cast<sockaddr*>(&me), &len) != 0) return Fail(HostError());
    std::memcpy(HostPtr(a[1]), &me, sizeof(me));
    W32(a[2], sizeof(me));
    return 0;
}
HLE_STDCALL(bind, 3) {
    Socket k = Find(a[0]);
    if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
    sockaddr_in at = GuestAddr(a[1]);
    if (g_instance && at.sin_addr.s_addr == INADDR_ANY) at.sin_addr.s_addr = g_local;
    if (::bind(k.s, reinterpret_cast<sockaddr*>(&at), sizeof(at)) != 0) {
        int e = HostError();
        LOGW("xnet: bind %X to %s failed (%d)", a[0], Addr(at).c_str(), e);
        return Fail(e);
    }
    LOGI("xnet: bind %X to %s", a[0], Addr(at).c_str());
    sockaddr_in me{};
    int len = sizeof(me);
    ::getsockname(k.s, reinterpret_cast<sockaddr*>(&me), &len);
    std::lock_guard<std::mutex> lock(g_lock);
    if (auto it = g_sockets.find(a[0]); it != g_sockets.end()) it->second.port = me.sin_port;
    return 0;
}
HLE_STDCALL(connect, 3) {
    Socket k = Find(a[0]);
    if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
    sockaddr_in to = GuestAddr(a[1]);
    LOGI("xnet: connect %X -> %s", a[0], Addr(to).c_str());
    if (::connect(k.s, reinterpret_cast<sockaddr*>(&to), sizeof(to)) == 0) return 0;
    int e = HostError();
    if (e != WSAEWOULDBLOCK || k.nonblocking) return Fail(e);
    if (!Wait(k.s, true, 10000)) return Fail(WSAETIMEDOUT);
    int err = 0, len = sizeof(err);
    ::getsockopt(k.s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
    return err ? Fail(err) : 0;
}
HLE_STDCALL(listen, 2) {
    Socket k = Find(a[0]);
    if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
    return ::listen(k.s, int(a[1])) == 0 ? 0 : Fail(WSAGetLastError());
}
// a blocking call that has waited this long says so once in the
// log (section 189): a guest thread parked inside one of the wait
// loops below is otherwise indistinguishable from a freeze - which
// is exactly what a stock System Link host looked like on device,
// its log ending mid-menu with nothing after
struct WaitNote {
    std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
    bool noted = false;
    void Tick(const char* what, uint32_t sock) {
        if (noted) return;
        if (std::chrono::steady_clock::now() - t0 < std::chrono::seconds(3)) return;
        noted = true;
        LOGI("xnet: %s %X still waiting after 3 s (blocking socket)", what, sock);
    }
};

HLE_STDCALL(accept, 3) {
    WaitNote note;
    for (;;) {
        Socket k = Find(a[0]);
        if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
        sockaddr_in from{};
        int len = sizeof(from);
        SOCKET s = ::accept(k.s, reinterpret_cast<sockaddr*>(&from), &len);
        if (s != INVALID_SOCKET) {
            if (a[1]) std::memcpy(HostPtr(a[1]), &from, sizeof(from));
            if (a[2]) W32(a[2], sizeof(from));
            LOGI("xnet: accept %X from %s", a[0], Addr(from).c_str());
            return AddSocket(s, false);
        }
        int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK || k.nonblocking) return Fail(e);
        Wait(k.s, false, 50);
        note.Tick("accept", a[0]);
    }
}
HLE_STDCALL(select, 5) {
    uint32_t guest[3] = {a[1], a[2], a[3]};
    fd_set host[3];
    std::vector<std::pair<uint32_t, SOCKET>> used[3];
    int total = 0;
    for (int i = 0; i < 3; i++) {
        FD_ZERO(&host[i]);
        if (!guest[i]) continue;
        uint32_t n = std::min(R32(guest[i]), kFdSetMax);
        for (uint32_t j = 0; j < n; j++) {
            uint32_t id = R32(guest[i] + 4 + 4 * j);
            Socket k = Find(id);
            if (k.s == INVALID_SOCKET) continue;
            FD_SET(k.s, &host[i]);
            used[i].push_back({id, k.s});
            total++;
        }
    }
    timeval tv{};
    timeval* ptv = nullptr;
    if (a[4]) {
        tv.tv_sec = long(R32(a[4]));
        tv.tv_usec = long(R32(a[4] + 4));
        ptv = &tv;
    }
    int r = 0;
    if (!total) {
        if (ptv) Sleep(DWORD(tv.tv_sec * 1000 + tv.tv_usec / 1000));
    } else {
        // a select with no timeout parks the guest until a socket
        // is ready; on an empty LAN that can be forever (section
        // 189) - leave a marker so the hang names itself
        if (!ptv) LOG_FIRST(10, "xnet: select waits with no timeout on %d socket(s)", total);
        // nfds must cover the highest host fd in the sets; with the
        // Winsock-style 0 this select could never report a ready
        // socket, so a guest waiting on it for a session reply hung
        // forever when nobody answered (section 144).
        int nfds = 0;
        for (int i = 0; i < 3; i++)
            for (auto& [id, s] : used[i]) nfds = std::max(nfds, int(s) + 1);
        r = ::select(nfds, guest[0] ? &host[0] : nullptr, guest[1] ? &host[1] : nullptr, guest[2] ? &host[2] : nullptr, ptv);
        if (r < 0) return Fail(HostError());
    }
    for (int i = 0; i < 3; i++) {
        if (!guest[i]) continue;
        uint32_t k = 0;
        for (auto& [id, s] : used[i])
            if (FD_ISSET(s, &host[i])) W32(guest[i] + 4 + 4 * k++, id);
        W32(guest[i], k);
    }
    return uint32_t(r);
}

HLE_STDCALL(recvfrom, 6) {
    std::vector<Span> spans{{a[1], a[2]}};
    WaitNote note;
    for (;;) {
        Socket k = Find(a[0]);
        if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
        int err = 0;
        int n;
        {
            std::lock_guard<std::mutex> lock(g_lock);
            n = Recv(a[0], k.s, spans, a[4], a[5], err);
        }
        if (n >= 0) return uint32_t(n);
        if (err != WSAEWOULDBLOCK || k.nonblocking) return Fail(err);
        Wait(k.s, false, 50);
        note.Tick("recvfrom", a[0]);
    }
}
// stream sockets; a reset connection is an error here, not a stale port unreachable reply
HLE_STDCALL(recv, 4) {
    WaitNote note;
    for (;;) {
        Socket k = Find(a[0]);
        if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
        int n = ::recv(k.s, static_cast<char*>(HostPtr(a[1])), int(a[2]), int(a[3]));
        if (n >= 0) return uint32_t(n);
        int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK || k.nonblocking) return Fail(e);
        Wait(k.s, false, 50);
        note.Tick("recv", a[0]);
    }
}
HLE_STDCALL(send, 4) {
    for (;;) {
        Socket k = Find(a[0]);
        if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
        int n = ::send(k.s, static_cast<const char*>(HostPtr(a[1])), int(a[2]), int(a[3]));
        if (n >= 0) return uint32_t(n);
        int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK || k.nonblocking) return Fail(e);
        Wait(k.s, true, 50);
    }
}
HLE_STDCALL(sendto, 6) {
    Socket k = Find(a[0]);
    if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
    sockaddr_in to{};
    if (a[4]) to = GuestAddr(a[4]);
    int n = Send(a[0], k.s, static_cast<const uint8_t*>(HostPtr(a[1])), int(a[2]), a[4] ? &to : nullptr);
    return n < 0 ? Fail(HostError()) : uint32_t(n);
}

namespace {

uint32_t SendOverlapped(uint32_t sock, uint32_t bufs, uint32_t count, uint32_t sent, uint32_t to_va, uint32_t ovl) {
    Socket k = Find(sock);
    if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
    auto data = Gather(bufs, count);
    sockaddr_in to{};
    if (to_va) to = GuestAddr(to_va);
    int n = Send(sock, k.s, data.data(), int(data.size()), to_va ? &to : nullptr);
    if (n < 0) return Fail(HostError());
    if (sent) W32(sent, uint32_t(n));
    if (ovl) Complete(ovl, 0, uint32_t(n));
    return 0;
}

uint32_t RecvOverlapped(uint32_t sock, uint32_t bufs, uint32_t count, uint32_t received, uint32_t flags, uint32_t from,
                        uint32_t fromlen, uint32_t ovl) {
    PendingRecv p{sock, ovl, from, fromlen, Spans(bufs, count)};
    WaitNote note;
    for (;;) {
        Socket k = Find(sock);
        if (k.s == INVALID_SOCKET) return Fail(WSAENOTSOCK);
        std::unique_lock<std::mutex> lock(g_lock);
        int err = 0;
        int n = Recv(sock, k.s, p.spans, from, fromlen, err);
        if (n >= 0) {
            if (received) W32(received, uint32_t(n));
            if (flags) W32(flags, 0);
            if (ovl) Complete(ovl, 0, uint32_t(n));
            return 0;
        }
        if (err != WSAEWOULDBLOCK) return Fail(err);
        if (ovl) {
            W32(ovl + kOvlStatus, kOvlPending);
            if (auto o = kernel::FromHandle(R32(ovl + kOvlEvent))) kernel::ResetEvent(*o);
            g_pending.push_back(std::move(p));
            return Fail(WSA_IO_PENDING);
        }
        if (k.nonblocking) return Fail(err);
        lock.unlock();
        Wait(k.s, false, 50);
        note.Tick("WSARecv", sock);
    }
}

}  // namespace

HLE_STDCALL(WSARecvFrom, 9) { return RecvOverlapped(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]); }
HLE_STDCALL(WSARecv, 7) { return RecvOverlapped(a[0], a[1], a[2], a[3], a[4], 0, 0, a[5]); }
HLE_STDCALL(WSASendTo, 9) { return SendOverlapped(a[0], a[1], a[2], a[3], a[5], a[7]); }
HLE_STDCALL(WSASend, 7) { return SendOverlapped(a[0], a[1], a[2], a[3], 0, a[5]); }

HLE_STDCALL(WSAGetOverlappedResult, 5) {
    uint32_t ovl = a[1];
    WaitNote note;
    for (;;) {
        {
            std::lock_guard<std::mutex> lock(g_lock);
            auto it = std::find_if(g_pending.begin(), g_pending.end(), [&](const PendingRecv& p) { return p.ovl == ovl; });
            if (it == g_pending.end() || TryComplete(*it)) {
                if (it != g_pending.end()) g_pending.erase(it);
                uint32_t status = R32(ovl + kOvlStatus);
                if (status == kOvlPending) {
                    t_error = WSA_IO_INCOMPLETE;
                    return 0;
                }
                if (a[2]) W32(a[2], R32(ovl + kOvlBytes));
                if (a[4]) W32(a[4], 0);
                if (status) {
                    t_error = status;
                    return 0;
                }
                return 1;
            }
        }
        if (!a[3]) {
            t_error = WSA_IO_INCOMPLETE;
            return 0;
        }
        Sleep(1);
        note.Tick("WSAGetOverlappedResult", ovl);
    }
}
HLE_STDCALL(WSACancelOverlappedIO, 1) {
    std::lock_guard<std::mutex> lock(g_lock);
    for (size_t i = 0; i < g_pending.size();) {
        if (g_pending[i].sock == a[0]) {
            Complete(g_pending[i].ovl, WSA_OPERATION_ABORTED, 0);
            g_pending.erase(g_pending.begin() + ptrdiff_t(i));
        } else {
            i++;
        }
    }
    return 0;
}
