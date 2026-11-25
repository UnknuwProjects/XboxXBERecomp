# Local patches

This fork tracks upstream XboxXBE-Recomp at the commit in `UPSTREAM_COMMIT`
and adds what the THPS4-Android port needs. Everything else is upstream code,
kept under its own license.

## Added

- `xdk/4928/` — XDK 4928 support, which upstream does not carry: function
  signatures and the device layout for the 4928 generation, recovered from
  Tony Hawk's Pro Skater 4 and verified against the game itself. Other 4928
  titles can build on this.
- `runtime/app/linknet.h` — the interface for carrying System Link sessions
  over the internet or a LAN through a small relay server.

## Changed

- `runtime/app/app.h` — the settings store the port's in-game options read
  and write.
- `runtime/xdk/xnet.cpp` — the linknet implementation behind `linknet.h`,
  plus wait notes on the blocking socket calls.
- `runtime/xdk/d3d8.h` / `d3d8.cpp` — the HLE also drains the pushbuffer
  streams the title's own D3D library builds, so library-built geometry
  (the particle systems among it) reaches the renderer.
- `runtime/kernel/boot.cpp`, `files.cpp`, `kernel.h` — the title's data
  folders are mounted as `T:` and `U:` at boot, as the console does at
  title launch; without them the save layer finds no save device.
- `runtime/kernel/memory.h` / `memory.cpp` — a 64 MB memory map with a
  mirror region, plus safe guest-memory reads for host code.
- `runtime/kernel/objects.cpp` — kernel waits funnel through one place, so
  timeouts and wakeups behave the same for every object type.
- `runtime/gpu/state.h`, `shaders.h`, `shaders.cpp` — default vertex
  attributes (`vattr`) are carried into the translated shaders instead of
  being hardcoded, adopted from ShaolinMonks-Android's copy of the same
  upstream pin.
- `runtime/core/log.h` / `log.cpp` — verbose diagnostics stay available in
  release builds, and the log keeps one fixed file name, which device bug
  reports rely on.
- `runtime/xdk/dsound.cpp` — stream creation and packet feeds are logged
  while music playback issues are being traced.

The game-specific work lives in the port repository; this fork only carries
the SDK-side changes.
