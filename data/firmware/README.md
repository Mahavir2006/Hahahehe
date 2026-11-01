# Firmware images for the attack demo

Illustrative source files that stand in for the Siemens SICAM PAS 8.2.1 firmware image on the Substation Gateway
(`power-asset-001`). They are not compilable and contain no real exploit: every `hal_*`, `crypto_*` and `auth_*`
call is fictional, and the beacon address is a documentation-only IP (203.0.113.0/24, never routable).

| File | Role |
|---|---|
| `sicam_pas_8.2.1/vendor_build.c` | The build the vendor signed and published. Its published hash is registered on the blockchain (`FirmwareRegistry`). |
| `sicam_pas_8.2.1/tampered_build.c` | The same build with three changes an attacker slipped into the update channel. |

The attack demo (`backend/attack_demo.py`) computes the SHA-256 of `tampered_build.c` at runtime and makes the
device report that hash, so the registry mismatch on the Attack Demo page is the real hash of the file shown there.

The three changes, and the detection each one triggers:

1. **Second signing key** (`BACKUP_PUBKEY`): future tampered images pass the signature check too. Caught by the
   on-chain firmware check: the running image's hash is not the published one.
2. **Hidden login** (`MAINT_MAGIC`): a fixed 16-byte value opens a maintenance session with no password, no MFA and
   no audit entry. Seen by the detection rules as an unexpected remote session from an unknown source, after the
   attacker's failed login attempts while probing.
3. **Beacon**: every 60 s the device sends its serial and live configuration to `203.0.113.42:4444`. Seen as
   outbound beaconing to an unknown host.
