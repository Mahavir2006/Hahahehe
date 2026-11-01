/*
 * SICAM PAS 8.2.1 - update_service.c
 * CascadeShield demo: ILLUSTRATIVE source standing in for the vendor-signed firmware image.
 * Not compilable and not a real device program: every hal_*, crypto_* and auth_* call is fictional.
 * The hash the vendor publishes for this build is registered on the blockchain (FirmwareRegistry).
 */
#include "hal.h"
#include "crypto.h"
#include "auth.h"

#define UPDATE_PORT        20000
#define MAINT_PORT         20001
#define SESSION_TIMEOUT_S  300

/* Vendor signing key, pinned at the factory. Only images signed with this key are ever installed. */
static const uint8_t VENDOR_PUBKEY[32] = { 0x5a, 0x1c, 0x9e, 0x44, /* ... */ };

/* ---- 1. Firmware update: only vendor-signed, newer images reach the flash ---------------------- */
static int verify_image(const image_t *img)
{
    if (!crypto_ed25519_verify(VENDOR_PUBKEY, img->payload, img->len, img->signature))
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

/* ---- 3. Main loop: the substation protocol and the two services above; nothing else uses the network */
void main_loop(void)
{
    for (;;) {
        iec61850_poll();                   /* substation telemetry to the control centre */
        update_service_poll(UPDATE_PORT);
        maint_service_poll(MAINT_PORT);
        hal_sleep_ms(50);
    }
}
