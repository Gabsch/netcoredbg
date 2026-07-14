# Vision Hot Reload DAP Extension

This fork is pinned to Samsung netcoredbg `3.2.0-1092` and adds the smallest DAP surface needed by Vision to use netcoredbg's existing Windows x64 Edit-and-Continue implementation.

The initialize response advertises `supportsVisionHotReload` and `visionHotReloadProtocolVersion = 1` only in builds compiled with `EnC_SUPPORTED`. Launch requests may set `enableHotReload = true`. Delta application uses `visionApplyHotReload` with `protocolVersion`, `moduleName`, and paths for metadata, IL, PDB, and netcoredbg line-update artifacts.

Attach-session Hot Reload and unsupported platforms are rejected explicitly. The fork remains MIT licensed; release payloads include the upstream license and pinned provenance.
