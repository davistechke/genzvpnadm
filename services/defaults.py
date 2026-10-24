"""The tweak every new panel starts with. It is added once, on first start, and can be edited or deleted freely."""
from models import Tweak, bump_rev, db, get_setting, set_setting

AIRTEL_CAP = {
    "name": "AIRTEL CAP", "country_code": "KE", "description": "Airtel", "protocol": "ssh",
    "host": 'suzuki.turbo-ssh.uk', "port": 443,
    "cfg": {"username": 'freedom', "password": 'decrypt', "payload": 'GET /cdn-cgi/trace HTTP/1.1[crlf]Host: [rotate=secure.3gdirectpay.com.https-t-me-neutrotech.onrender.com;airtelcareapp.airtelkenya.com;selfcare-media.airtelstream.net][crlf]User-Agent: [ua][crlf]Referer: [host][crlf][crlf]VERSION-CONTROL ws://[host] HTTP/1.1[crlf]Host: [host][crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf]User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html+t.me/rickytechwizard;advanced.net)[crlf][crlf]', "sni": "", "proxy_host": 'apptest.airtel.ug.https-t-me-neutrotech.onrender.com', "proxy_port": 80},
}


def seed_default_tweak():
    """Add AIRTEL CAP once, even if other tweaks already exist, so every panel starts with a working example to copy.
    After that it is an ordinary tweak: edit it, copy it, or delete it and it stays deleted."""
    if get_setting("default_seeded"):
        return
    if not Tweak.query.filter_by(name=AIRTEL_CAP["name"]).first():
        d = AIRTEL_CAP
        t = Tweak(name=d["name"], country_code=d["country_code"], description=d["description"], protocol=d["protocol"],
                  host=d["host"], port=d["port"], sort=0, is_active=True)
        t.cfg = d["cfg"]
        db.session.add(t)
        bump_rev()
    set_setting("default_seeded", "1")
    db.session.commit()
