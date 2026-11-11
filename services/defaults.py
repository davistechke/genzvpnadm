"""The tweak every new panel starts with. It is added once, on first start, and can be edited or deleted freely."""
from models import Tweak, bump_rev, db, get_setting, set_setting

AIRTEL_CAP = {
    "name": "AIRTEL CAP", "country_code": "KE", "description": "Airtel", "protocol": "ssh",
    "host": 'suzuki.turbo-ssh.uk', "port": 443,
    "cfg": {"username": 'freedom', "password": 'decrypt', "payload": 'GET /cdn-cgi/trace HTTP/1.1[crlf]Host: [rotate=secure.3gdirectpay.com.https-t-me-neutrotech.onrender.com;airtelcareapp.airtelkenya.com;selfcare-media.airtelstream.net][crlf]User-Agent: [ua][crlf]Referer: [host][crlf][crlf]VERSION-CONTROL ws://[host] HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf]User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html+t.me/rickytechwizard;advanced.net)[crlf][crlf]', "sni": "", "proxy_host": 'apptest.airtel.ug.https-t-me-neutrotech.onrender.com', "proxy_port": 80},
}


TELKOM_UNLIMITED = {
    "name": "TELKOM UNLIMITED", "country_code": "KE", "description": "Telkom", "protocol": "ssh",
    "host": "172.235.157.43", "port": 443,
    # The account below is an assumption (the same login as AIRTEL CAP). Edit the tweak if your Telkom server uses another.
    "cfg": {"username": "freedom", "password": "decrypt", "payload": '[method] [host_port] [protocol][crlf]Host: [host][crlf]Service: SSH[crlf]Mode: Bypass[crlf][crlf]',
            "sni": "myaccount.telkom.co.ke", "proxy_host": "", "proxy_port": 0},
}


def _add(d, sort):
    t = Tweak(name=d["name"], country_code=d["country_code"], description=d["description"], protocol=d["protocol"],
              host=d["host"], port=d["port"], sort=sort, is_active=True)
    t.cfg = d["cfg"]
    db.session.add(t)


def seed_default_tweak():
    """Add the default tweaks once each, even if other tweaks exist, so every panel starts with working examples to copy.
    After that they are ordinary tweaks: edit, copy or delete them and a deleted one stays deleted."""
    changed = False
    if not get_setting("default_seeded"):
        if not Tweak.query.filter_by(name=AIRTEL_CAP["name"]).first():
            _add(AIRTEL_CAP, 0)
        set_setting("default_seeded", "1")
        changed = True
    if not get_setting("default_seeded_telkom"):
        if not Tweak.query.filter_by(name=TELKOM_UNLIMITED["name"]).first():
            _add(TELKOM_UNLIMITED, 1)
        set_setting("default_seeded_telkom", "1")
        changed = True
    if changed:
        bump_rev()
    db.session.commit()
