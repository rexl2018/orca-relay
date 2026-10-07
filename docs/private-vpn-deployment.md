# Private VPN deployment from source

Use this topology for an operator-authorized private network with an existing
VPN. Public deployments still need trusted TLS and loopback upstreams. Do not
expose the raw proxy on the public internet.

```text
iPhone + existing VPN -> private server: proxy /, /ws or /r/<server-id>
                        -> loopback relay /ws
Mac bridge -> SSH local forward -> loopback relay /ws
           -> already-running local Orca mobile WebSocket
```

The phone needs the Orca app and its existing VPN. Bind the relay to loopback
and the proxy to the specific interface reachable through the VPN. SSH protects
the Mac uplink. Orca Relay adds no payload encryption; raw `ws://` legs depend on
the private network's transport protections.

## Build and record provenance

Inspect `AGENTS.md`, manifests, source, lockfile and scripts before executing them.
Use the operator's fork and existing trusted Rust toolchains on Mac and Linux:

```sh
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --locked --release --bins
```

Compile Linux binaries on Linux and Mac binaries on Mac. Transfer only reviewed
source, the lockfile and tests; omit `target/`, filled env files and pairing
material. Record the source commit, any working diff and SHA-256 values for the
source and binaries. Do not describe a dirty-tree build as an unmodified release.
Do not run downloaded installers or unidentified helpers.

## Supervise the server and Mac uplink

Install the self-built Linux binaries under an operator-owned release path and
create dedicated systemd relay/proxy units with private `EnvironmentFile` files,
`Restart=on-failure` and explicit addresses. For a same-host proxy, use
`ORCA_RELAY_URL=ws://127.0.0.1:8080/ws`. Adapters share the relay token; each
selected runtime ID must match its own bridge. Give each proxy its own client ID.
One proxy listener can keep a default `ORCA_RELAY_SERVER_ID` and explicit extra
IDs in comma-separated `ORCA_RELAY_SERVER_IDS`. Its `/` and `/ws` paths keep the
default; `/r/<server-id>` selects a configured target on the same port. Unknown
IDs return HTTP 404. Each runtime still needs one bridge.
Omit the extra-ID variable when unused. Empty entries, IDs equal to `.` or `..`,
and additional IDs containing path separators or control characters prevent startup. URL-encode
each named ID as one path segment. The proxy port has no authentication of its
own: reachability permits connection attempts to every configured target, while
each runtime validates its Orca pairing credentials. Bind only to loopback or
the intended private VPN interface.
Generate the token into a private file and
transfer it over SSH without printing it. Leave unrelated services alone.

On Mac, use separate user LaunchAgents for these processes:

1. SSH with `-N -T`, `BatchMode=yes`, `ExitOnForwardFailure=yes`, keepalives and
   `-L 127.0.0.1:<local-relay-port>:127.0.0.1:8080 <ssh-host>`.
2. The self-built bridge, reading a private JSON file containing the forwarded
   loopback relay URL ending in `/ws`, local runtime URL, routing ID and token.

Keep secrets out of LaunchAgent XML and argv. The reviewed
`scripts/launch-macos-bridge.py` reads an owner-only JSON file and `exec`s the
bridge without printing config. All LaunchAgent program, launcher, config and binary
paths must be absolute; launchd does not expand `~` or shell variables. Use these four keys: `ORCA_RELAY_URL`,
`ORCA_RUNTIME_WS_URL`, `ORCA_RELAY_SERVER_ID` and `ORCA_RELAY_TOKEN`.
Retry startup failures, while
allowing a bridge replaced by another bridge to stay stopped after successful exit.
For launchd, use `KeepAlive` with `SuccessfulExit=false` for the bridge, and
continuous supervision for the SSH tunnel.
Keep the existing GUI runtime separate; do not apply Linux tmux/Xvfb scripts to a
Mac or start another runtime on its port.
If login startup is required, use a separate `RunAtLoad` LaunchAgent that invokes
the system `open -g -a <existing-Orca-app-path>`. Do not give this one-shot opener
continuous `KeepAlive`; opening an already-running app must preserve its process.

## Add another runtime

Give each additional host its own routing ID, bridge and native Orca mobile
pairing identity. Add the ID to the existing proxy's explicit extra-ID list.
On another Mac, generate the mobile offer in that Mac's Orca Settings → Mobile;
starting the GUI alone does not create a mobile identity. Keep its GUI, SSH
tunnel and bridge separate, as above.

For a Linux host without a desktop, inspect the installed official Orca CLI
before using its headless `serve --port <orca-runtime-port> --mobile-pairing
--json` path. Identify and verify the Orca package and required Xvfb package
before running them. Supervise the foreground runtime and the bridge separately.
Keep readiness output private: it can contain both the pairing URL and its QR
representation. Check the actual bound port; the requested port can fall back.
For the inspected Orca 1.4.221, read the first JSON record with
`type=orca_server_ready` and `schemaVersion=1`. Its `boundEndpoint` is a string
URL; parse the port from that URL. Require `pairing.available=true` and mobile
scope. Both `pairing.url` and `pairing.qr` contain secrets.
The inspected Orca 1.4.221 headless runtime binds to all interfaces, so install a
persistent, port-specific non-loopback access restriction before startup. Leave
existing firewall rules and relay/proxy services alone.

On a genuinely fresh Orca 1.4.221 Linux profile, an owner-only
`~/.config/orca/orca-data.json` containing
`{"settings":{"agentStatusHooksEnabled":false}}` prevents startup from
installing hooks into existing agent configurations. Confirm there are no
`profile-state.db*`, `orca-profile-index.json*`, `profiles/` or
`orca-data.json.bak.*` before seeding it; preserve existing
settings on an established profile. The official hook-disable command also
removes hook entries, so it is unsuitable when those configurations must stay
unchanged. Record their hashes before startup and compare afterward.

## Pair privately, then verify

Obtain a **mobile-scoped** offer using the pairing UI/IPC/CLI supported by the
installed Orca version. Persist it with mode `0600`. Rewrite only `endpoint` to
`ws://<private-vpn-host>:<proxy-port>/`, preserving all other fields. The root
endpoint supports mobile address editors that reject `/ws`.
For a named runtime, use that runtime's own mobile-scoped offer and rewrite its
endpoint to `ws://<private-vpn-host>:<proxy-port>/r/<server-id>`. Preserve the full
path during QR pairing and verify it in the private offer. Credentials from one
runtime must not be reused to pair another runtime.

Do not put pairing codes in argv, logs, git or screenshots. The existing rewrite
CLI accepts a positional code; use a reviewed private-file helper or the library
when process arguments must remain secret. Verify that every other offer field
remains equal, including scope and credentials.

Verify loopback relay health, proxy socket upgrade, SSH forwarding, bridge
registration, and an authenticated real Orca RPC over each selected proxy route. Then verify the
iPhone VPN path, terminal read/input, network change and Mac wake. Synthetic echoes
and health checks do not prove phone access; leave device-only checks pending until
observed. Rollback affects only the newly installed services, release link and
private configuration, preserving the existing Orca app.
