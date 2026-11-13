# Memberra for Silo

A [Silo](https://siloserver.org) plugin that connects a Silo server to Memberra without the Memberra agent. It keeps an outbound, signed connection, so the server needs no open port or public URL.

Memberra can then create, suspend, restore and delete customer accounts, set their libraries, and apply package limits (streams, transcoding, downloads and remote bitrate). The plugin accepts only these fixed commands. It never changes Silo admin or owner accounts, and it can't run anything else on the server.

## Install

1. In Memberra, open **Infrastructure → Silo plugin** and press **Pair a Silo server**.
2. In Silo, go to **Admin → Plugins → Repositories**, add this repository URL and install **Memberra** from the catalogue:

   `https://raw.githubusercontent.com/MrSynthetic/memberra-silo-plugin/main/repository.json`

   Or download the binary for your platform from [Releases](https://github.com/MrSynthetic/memberra-silo-plugin/releases) (`plugin-linux-amd64` on most servers) and upload it under **Admin → Plugins**.
3. In Silo, create an API key while signed in as an admin. Scopes `admin:users` and `libraries:read` are enough; a key with those scopes can't change admin accounts.
4. Open the Memberra plugin's settings, paste the pairing code and the API key, save, then press **Check connection**.

The server appears in Memberra within a few seconds. The pairing code works once; the plugin then keeps a revocable token in Silo's encrypted plugin state. Revoking the install in Memberra stops it until a new code is entered.

## How it works

- Silo starts the plugin's **Memberra connection** task when Silo starts. The task starts a loop that sends a heartbeat every 10 seconds, with the server's libraries.
- Memberra's reply carries any queued commands. The plugin runs each one against Silo's admin API (`/api/v2/admin/users`) and acknowledges the result.
- Requests use Memberra's media-plugin protocol v4, shared with the Jellyfin plugin: `Bearer <installId>.<token>` plus an HMAC-SHA256 signature over the method, path, timestamp, single-use nonce and body hash.
- Silo rules it follows: every write sends the account's ETag; "all libraries" is sent as `null` (an empty list would mean no libraries); suspending or resetting a password also signs the account out.

Not included yet: watch history. Memberra's watch tables don't accept Silo yet.

## Build

Requires Go 1.26.

```sh
go test -race ./...
./build.sh            # dist/memberra-silo-<version>-<os>-<arch> and .sha256 files
```

The binary embeds its manifest and computes its own checksum, so it can be uploaded to Silo directly.
