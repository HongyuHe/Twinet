#!/usr/bin/env python3
"""Connect the missing hostapd KaY offload callback to its Linux driver."""
import hashlib
from pathlib import Path
import sys
root=Path(sys.argv[1]);p=root/'hostap/hostapd-2.12/src/ap/wpa_auth_kay.c';s=p.read_text();out=root/'exports/hostap-offload-repair';out.mkdir(parents=True,exist_ok=False)
(out/'wpa_auth_kay.before.c').write_text(s)
assert 'kay_ctx->set_offload' not in s
at=s.index('static int hapd_set_current_cipher_suite')
s=s[:at]+"""static int hapd_set_offload(void *priv, u8 offload)
{
    struct hostapd_data *hapd = priv;
    if (!hapd->driver->set_offload)
        return -1;
    return hapd->driver->set_offload(hapd->drv_priv, offload);
}


"""+s[at:]
s=s.replace('kay_ctx->set_replay_protect = hapd_set_replay_protect;','kay_ctx->set_replay_protect = hapd_set_replay_protect;\n\tkay_ctx->set_offload = hapd_set_offload;')
p.write_text(s);(out/'wpa_auth_kay.after.c').write_text(s)
for f in out.iterdir():print(f.name,hashlib.sha256(f.read_bytes()).hexdigest())
