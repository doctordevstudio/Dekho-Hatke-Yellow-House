import os
import re
import json
import time
import hmac
import hashlib
import asyncio
import base64
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin, urlparse
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.templating import Jinja2Templates
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import firebase_admin
from firebase_admin import credentials, db

# ==============================================================================
# 1. CONFIGURATION
# ==============================================================================
AES_KEY = bytes.fromhex(os.getenv(
    "APP_AES_HEX_KEY",
    "8f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a"
))
HMAC_KEY = bytes.fromhex(os.getenv(
    "APP_HMAC_HEX_KEY",
    "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
))

EXPECTED_APK_SIG = os.getenv(
    "EXPECTED_APK_SIG_SHA256",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
EXPECTED_VERSION_NAME = os.getenv("EXPECTED_APP_VERSION_NAME", "1.0.0")
EXPECTED_VERSION_CODE = int(os.getenv("EXPECTED_APP_VERSION_CODE", "1"))

LICENSE_PROVIDER_URL = os.getenv(
    "LICENSE_PROVIDER_URL",
    "https://dekhohatke.onrender.com/api/v1/app_0c14dba1e3b7/verify"
)
LICENSE_PROVIDER_API_KEY = os.getenv("LICENSE_PROVIDER_API_KEY", "")

FIREBASE_DB_URL = os.getenv("FIREBASE_DB_URL", "https://faphouse-default-rtdb.firebaseio.com/")
FIREBASE_SA_RAW = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", "")
ADMIN_SECRET_TOKEN = os.getenv("ADMIN_SECRET_TOKEN", "DrHamzaAdmin2026!")

DEFAULT_PREMIUM_COOKIES = (
    "guid=0eykase26eps00ow8wggw0k00o; sex_orientation=straight; "
    "__fp=217f4c2d7b4968ed1e9d2403ea9f656c; cookie-settings=%7B%22all%22%3A1%2C%22strict%22%3A0%7D; "
    "prs=--; PHPSESSID=51fafecbfe55c542dc5e07d85861501d; "
    "_identity=aed548e4baff400bfa045e088ae21c02e1484f56f6efc1c0a9b29e4023246ff9a%3A2%3A%7Bi%3A0%3Bs%3A9%3A%22_identity%22%3Bi%3A1%3Bs%3A89%3A%22%5B122817693%2C%222VSu3hNOpMldyhSwGzEZKYcK3glICYWS%22%2C2592000%2C%2251fafecbfe55c542dc5e07d85861501d%22%5D%22%3B%7D; "
    "siteMode=mobile; locale=en; translate-video-titles=1; appearance=dark; user_device_theme=dark; "
    "intro_state=%7B%22cookie-wall-short-shown%22%3A%5B%22Y%22%2C1793969215%5D%2C%22fh-video-orientation-filter-note%22%3A%5B1%2C1824195777%5D%2C%22ultraSecondStep%22%3A%5B%22-1%22%2C0%5D%2C%22ultraSelected%22%3A%5B%22false%22%2C0%5D%2C%22subtitle-hint%22%3A%5B1%2C1824217098%5D%2C%22ultra-subtitles-unlock-video-ids%22%3A%5B%22%5B6454553%5D%22%2C1792832539%5D%2C%22fh-fan-promo%22%3A%5B1%2C1792822799%5D%2C%22fh-feed-title-note%22%3A%5B1%2C1824355426%5D%2C%22fh-post-title-note%22%3A%5B1%2C1824355426%5D%7D"
)
PREMIUM_COOKIES = os.getenv("PREMIUM_COOKIES", DEFAULT_PREMIUM_COOKIES)

UPSTREAM_UA = (
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0.0.0 Safari/537.36"
)

CDN_HOST_ALLOWLIST = (
    "fhcdngroup.online",
    "flixcdn.com",
    "faphouse.com",
    "faphouse2.com",
    "xhcdn.com",
)

# ==============================================================================
# 2. FIREBASE
# ==============================================================================
def init_firebase():
    if firebase_admin._apps:
        return
    try:
        if FIREBASE_SA_RAW.strip().startswith("{"):
            sa_dict = json.loads(FIREBASE_SA_RAW)
            cred = credentials.Certificate(sa_dict)
        elif os.path.exists(FIREBASE_SA_RAW):
            cred = credentials.Certificate(FIREBASE_SA_RAW)
        else:
            cred = None
        if cred:
            firebase_admin.initialize_app(cred, {"databaseURL": FIREBASE_DB_URL})
            print("[+] Firebase initialized.")
    except Exception as e:
        print(f"[!] Firebase init error: {e}")


MEM_STATE: Dict[str, Any] = {
    "licenses": {},
    "blocked_users": {},
    "rate_limits": {},
    "shadow_banned": {},
    "update_config": {
        "enabled": False,
        "version_name": "1.0.0",
        "version_code": 1,
        "features": "",
        "update_url": "https://t.me/drdevstudio",
        "force_update": True,
    },
    "premium_cookies": PREMIUM_COOKIES,
}


def fb_ref(subpath: str = ""):
    if not firebase_admin._apps:
        return None
    return db.reference(f"Faphouse/{subpath}" if subpath else "Faphouse")


async def sync_from_firebase():
    ref = fb_ref()
    if not ref:
        return
    try:
        data = await asyncio.to_thread(ref.get)
        if isinstance(data, dict):
            for k in ["licenses", "blocked_users", "rate_limits", "shadow_banned",
                      "update_config", "premium_cookies"]:
                if k in data and data[k] is not None:
                    MEM_STATE[k] = data[k]
    except Exception as e:
        print(f"[!] Firebase sync error: {e}")


async def sync_node_to_firebase(node: str, key: Optional[str] = None, value: Any = None):
    ref = fb_ref(f"{node}/{key}" if key else node)
    if not ref:
        return
    try:
        await asyncio.to_thread(ref.set, value)
    except Exception as e:
        print(f"[!] Firebase write error ({node}): {e}")

# ==============================================================================
# 3. LIFESPAN
# ==============================================================================
http_client: Optional[httpx.AsyncClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    init_firebase()
    await sync_from_firebase()
    limits = httpx.Limits(max_keepalive_connections=60, max_connections=200)
    http_client = httpx.AsyncClient(
        http2=True,
        timeout=httpx.Timeout(20.0, connect=10.0, read=45.0),
        limits=limits,
        follow_redirects=True,
    )
    yield
    if http_client:
        await http_client.aclose()


app = FastAPI(
    title="Dr. Dev Secure FapHouse Backend",
    docs_url=None, redoc_url=None, openapi_url=None,
    lifespan=lifespan,
)
os.makedirs("templates", exist_ok=True)
templates = Jinja2Templates(directory="templates")

# ==============================================================================
# 4. ENVELOPE CRYPTO
# ==============================================================================
USED_NONCES: Dict[str, float] = {}


def clean_old_nonces():
    now = time.time()
    expired = [n for n, ts in USED_NONCES.items() if now - ts > 120]
    for n in expired:
        USED_NONCES.pop(n, None)


def decrypt_and_verify_payload(envelope: Dict[str, str]) -> Dict[str, Any]:
    try:
        b64_data = envelope["d"]
        sig_hex = envelope["s"]
        ts_str = envelope["t"]
        req_nonce = envelope["n"]
    except KeyError:
        raise HTTPException(status_code=400, detail="Malformed envelope")

    now = time.time()
    try:
        req_ts = int(ts_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid timestamp")

    if abs(now - req_ts) > 90:
        raise HTTPException(status_code=403, detail="Request timestamp expired")

    clean_old_nonces()
    if req_nonce in USED_NONCES:
        raise HTTPException(status_code=403, detail="Replay detected")
    USED_NONCES[req_nonce] = now

    raw_bytes = base64.b64decode(b64_data)
    if len(raw_bytes) < 28:
        raise HTTPException(status_code=400, detail="Invalid cipher length")

    payload_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    signing_string = f"{ts_str}:{req_nonce}:{payload_sha256}".encode("utf-8")
    expected_hmac = hmac.new(HMAC_KEY, signing_string, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_hmac, sig_hex):
        raise HTTPException(status_code=403, detail="Invalid HMAC")

    gcm_nonce = raw_bytes[:12]
    ct_tag = raw_bytes[12:]
    aesgcm = AESGCM(AES_KEY)
    try:
        aad = f"{ts_str}:{req_nonce}".encode("utf-8")
        decrypted = aesgcm.decrypt(gcm_nonce, ct_tag, aad)
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=403, detail="Decryption failed")


def encrypt_and_sign_response(data: Dict[str, Any]) -> Dict[str, str]:
    plaintext = json.dumps(data, separators=(",", ":")).encode("utf-8")
    ts_str = str(int(time.time()))
    resp_nonce = base64.urlsafe_b64encode(os.urandom(12)).decode("utf-8").rstrip("=")
    gcm_nonce = os.urandom(12)
    aad = f"{ts_str}:{resp_nonce}".encode("utf-8")

    aesgcm = AESGCM(AES_KEY)
    ct = aesgcm.encrypt(gcm_nonce, plaintext, aad)
    combined = gcm_nonce + ct
    b64_data = base64.b64encode(combined).decode("utf-8")

    payload_sha256 = hashlib.sha256(combined).hexdigest()
    signing_string = f"{ts_str}:{resp_nonce}:{payload_sha256}".encode("utf-8")
    sig_hex = hmac.new(HMAC_KEY, signing_string, hashlib.sha256).hexdigest()

    return {"d": b64_data, "s": sig_hex, "t": ts_str, "n": resp_nonce}

# ==============================================================================
# 5. HLS STREAM SESSIONS
# ==============================================================================
STREAM_SESSIONS: Dict[str, Dict[str, Any]] = {}
STREAM_SESSION_TTL = 7200


def b64url_enc(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8").rstrip("=")


def b64url_dec(s: str) -> str:
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + ("=" * pad)).decode("utf-8")


def cleanup_sessions():
    now = int(time.time())
    expired = [k for k, v in STREAM_SESSIONS.items()
               if now - v.get("created", 0) > STREAM_SESSION_TTL]
    for k in expired:
        STREAM_SESSIONS.pop(k, None)


def mint_stream_session(master_url: str, license_key: str) -> str:
    cleanup_sessions()
    session_id = base64.urlsafe_b64encode(os.urandom(24)).decode("utf-8").rstrip("=")
    STREAM_SESSIONS[session_id] = {
        "master_url": master_url,
        "license_key": license_key,
        "created": int(time.time()),
        "last_used": int(time.time()),
    }
    return session_id


def is_allowed_upstream(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return any(host == d or host.endswith("." + d) for d in CDN_HOST_ALLOWLIST)
    except Exception:
        return False


def rewrite_playlist(text: str, base_url: str, session_id: str) -> str:
    out_lines: List[str] = []
    proxy_prefix = f"https://fhp.local/hls/{session_id}"

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            out_lines.append("")
            continue

        if line.startswith("#EXT-X-KEY") or line.startswith("#EXT-X-MAP") or \
           line.startswith("#EXT-X-MEDIA") or line.startswith("#EXT-X-SESSION-KEY"):
            def _rewrite(m):
                uri = m.group(1)
                abs_url = urljoin(base_url, uri)
                if not is_allowed_upstream(abs_url):
                    return f'URI="{uri}"'
                encoded = b64url_enc(abs_url)
                ext = uri.split("?")[0].rsplit(".", 1)[-1].lower()
                kind = "key" if ext in ("key", "bin") else "seg"
                return f'URI="{proxy_prefix}/{kind}/{encoded}"'
            out_lines.append(re.sub(r'URI="([^"]+)"', _rewrite, line))
        elif line.startswith("#"):
            out_lines.append(raw)
        else:
            abs_url = urljoin(base_url, line)
            if not is_allowed_upstream(abs_url):
                out_lines.append(raw)
                continue
            ext = abs_url.split("?")[0].rsplit(".", 1)[-1].lower()
            kind = "var" if ext == "m3u8" else "seg"
            encoded = b64url_enc(abs_url)
            out_lines.append(f"{proxy_prefix}/{kind}/{encoded}")

    return "\n".join(out_lines) + "\n"


def guess_content_type(url_or_name: str) -> str:
    p = url_or_name.split("?")[0].lower()
    if p.endswith(".m3u8"):
        return "application/vnd.apple.mpegurl"
    if p.endswith(".ts"):
        return "video/mp2t"
    if p.endswith(".mp4"):
        return "video/mp4"
    if p.endswith(".m4s") or p.endswith(".m4a") or p.endswith(".m4v"):
        return "video/iso.segment"
    if p.endswith(".aac"):
        return "audio/aac"
    if p.endswith(".vtt") or p.endswith(".webvtt"):
        return "text/vtt"
    return "application/octet-stream"

# ==============================================================================
# 6. SECURITY
# ==============================================================================
def check_device_blocked(device_id: str) -> Optional[Dict[str, Any]]:
    now = int(time.time())
    entry = MEM_STATE["blocked_users"].get(device_id)
    if entry:
        if entry.get("blocked_until", 0) > now:
            return {
                "blocked": True,
                "remaining_seconds": entry["blocked_until"] - now,
                "message": "Maximum 3 failed attempts reached. Your device is blocked for 24 hours.",
            }
        else:
            MEM_STATE["blocked_users"].pop(device_id, None)
            asyncio.create_task(sync_node_to_firebase("blocked_users", device_id, None))
    return None


async def record_failed_attempt(device_id: str, client_ip: str):
    now = int(time.time())
    entry = MEM_STATE["blocked_users"].get(device_id, {
        "device_id": device_id, "ip": client_ip,
        "failed_attempts": 0, "blocked_until": 0, "last_attempt": now,
    })
    entry["failed_attempts"] = entry.get("failed_attempts", 0) + 1
    entry["last_attempt"] = now
    if entry["failed_attempts"] >= 3:
        entry["blocked_until"] = now + 86400
        entry["reason"] = "3 Failed License Attempts"
    MEM_STATE["blocked_users"][device_id] = entry
    await sync_node_to_firebase("blocked_users", device_id, entry)
    return entry


async def verify_integrity(payload: Dict[str, Any], device_id: str) -> bool:
    if device_id in MEM_STATE["shadow_banned"]:
        return True
    apk_sig = payload.get("apk_sig", "")
    ver_name = payload.get("app_version", "")
    ver_code = int(payload.get("version_code", 0))
    env_tampered = bool(payload.get("env_flags", 0))

    reasons = []
    if EXPECTED_APK_SIG and apk_sig != EXPECTED_APK_SIG:
        reasons.append("APK_SIGNATURE_MISMATCH")
    if ver_name != EXPECTED_VERSION_NAME or ver_code != EXPECTED_VERSION_CODE:
        reasons.append(f"VERSION_PATCHED({ver_name}:{ver_code})")
    if env_tampered:
        reasons.append(f"NATIVE_ENV_FLAGS({payload.get('env_flags')})")

    if reasons:
        ban_info = {
            "device_id": device_id,
            "reason": ", ".join(reasons),
            "timestamp": int(time.time()),
            "apk_sig": apk_sig,
            "version_name": ver_name,
            "version_code": ver_code,
        }
        MEM_STATE["shadow_banned"][device_id] = ban_info
        await sync_node_to_firebase("shadow_banned", device_id, ban_info)
        return True
    return False


async def verify_license(license_key: str, device_id: str, device_name: str, app_version: str) -> Dict[str, Any]:
    if not http_client:
        return {"http_status": 503, "success": False, "code": "NETWORK_ERROR",
                "message": "Backend not ready."}
    headers = {"Content-Type": "application/json", "X-API-Key": LICENSE_PROVIDER_API_KEY}
    payload = {
        "license_key": license_key,
        "device_id": device_id,
        "device_name": device_name or "Android Device",
        "app_version": app_version or EXPECTED_VERSION_NAME,
    }
    try:
        resp = await http_client.post(LICENSE_PROVIDER_URL, json=payload, headers=headers, timeout=10.0)
        body = resp.json()
        body["http_status"] = resp.status_code
        return body
    except Exception:
        return {"http_status": 503, "success": False, "code": "NETWORK_ERROR",
                "message": "Unable to reach license server."}

# ==============================================================================
# 7. HTML PARSER
# ==============================================================================
RE_JSON_LD = re.compile(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
RE_TITLE = re.compile(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
RE_THUMB = re.compile(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
RE_DURATION_META = re.compile(r'<meta[^>]+property=["\']video:duration["\'][^>]+content=["\'](\d+)["\']', re.IGNORECASE)
RE_M3U8_URLS = re.compile(r'https?://[^\s"\'<>\\]+\.m3u8[^\s"\'<>\\]*', re.IGNORECASE)
RE_MP4_URLS = re.compile(r'https?://[^\s"\'<>\\]+\.mp4[^\s"\'<>\\]*', re.IGNORECASE)
RE_VTT_URLS = re.compile(r'https?://[^\s"\'<>\\]+\.vtt[^\s"\'<>\\]*', re.IGNORECASE)
RE_STUDIO_NAME = re.compile(r'data-el-studio-name=["\']([^"\']+)["\']', re.IGNORECASE)
RE_VIDEO_DURATION_ATTR = re.compile(r'data-el-duration=["\'](\d+)["\']', re.IGNORECASE)


def format_duration(seconds: int) -> str:
    if seconds <= 0:
        return "00:00"
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def estimate_size_mb(duration_sec: int, resolution: str) -> float:
    br = {"2160p": 8500, "4k": 8500, "1440p": 5500, "1080p": 3400,
          "720p": 1850, "480p": 950, "360p": 600, "240p": 350}
    res = resolution.lower()
    kbps = next((v for k, v in br.items() if k in res), 1800)
    return round((max(duration_sec, 180) * kbps) / 8.0 / 1024.0, 2)


async def parse_master_playlist(master_url: str, duration: int, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    qualities = []
    if not http_client:
        return qualities
    try:
        r = await http_client.get(master_url, headers=headers)
        if r.status_code != 200:
            return qualities
        lines = [ln.strip() for ln in r.text.splitlines() if ln.strip()]
        base = master_url.rsplit("/", 1)[0] + "/"
        for i, line in enumerate(lines):
            if line.startswith("#EXT-X-STREAM-INF"):
                res_m = re.search(r'RESOLUTION=\d+x(\d+)', line)
                bw_m = re.search(r'BANDWIDTH=(\d+)', line)
                height = res_m.group(1) if res_m else "720"
                label = f"{height}p"
                bandwidth = int(bw_m.group(1)) if bw_m else 0
                if i + 1 < len(lines) and not lines[i + 1].startswith("#"):
                    uri = lines[i + 1]
                    if not uri.startswith("http"):
                        uri = base + uri
                    size_mb = round((bandwidth * duration) / 8.0 / (1024 * 1024), 2) \
                              if bandwidth and duration else estimate_size_mb(duration, label)
                    qualities.append({
                        "quality": label, "url": uri, "type": "m3u8",
                        "bandwidth": bandwidth, "size_mb": size_mb,
                    })
    except Exception:
        pass
    return qualities


async def fetch_premium_video_data(video_url: str, license_key: str) -> Dict[str, Any]:
    if not http_client:
        raise RuntimeError("HTTP client not initialized")

    headers = {
        "User-Agent": UPSTREAM_UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7",
        "Referer": "https://faphouse2.com/feed",
        "Cookie": MEM_STATE.get("premium_cookies", PREMIUM_COOKIES),
    }
    resp = await http_client.get(video_url, headers=headers)
    html = resp.text
    unescaped = html.replace("\\/", "/")

    title = "Premium Video"
    thumbnail = ""
    duration_sec = 0
    studio = "FapHouse Creator"
    preview_mp4 = ""
    m3u8_list: List[str] = []
    mp4_list: List[str] = []
    subtitles: List[Dict[str, str]] = []

    m = RE_TITLE.search(html)
    if m:
        title = m.group(1).strip()
    m = RE_THUMB.search(html)
    if m:
        thumbnail = m.group(1).strip()
    m = RE_DURATION_META.search(html) or RE_VIDEO_DURATION_ATTR.search(html)
    if m:
        duration_sec = int(m.group(1))
    m = RE_STUDIO_NAME.search(html)
    if m:
        studio = m.group(1).strip()

    for ld in RE_JSON_LD.finditer(html):
        try:
            j = json.loads(ld.group(1).strip())
            if isinstance(j, dict):
                title = j.get("name", title)
                tu = j.get("thumbnailUrl")
                if isinstance(tu, list) and tu:
                    thumbnail = tu[0]
                elif isinstance(tu, str):
                    thumbnail = tu
                cu = j.get("contentUrl", "")
                if cu.endswith(".m3u8"):
                    m3u8_list.append(cu)
                elif cu.endswith(".mp4"):
                    preview_mp4 = cu
        except Exception:
            pass

    for u in RE_M3U8_URLS.findall(unescaped):
        u = u.split('"')[0].split("'")[0].split("\\")[0]
        if u not in m3u8_list:
            m3u8_list.append(u)
    for u in RE_MP4_URLS.findall(unescaped):
        u = u.split('"')[0].split("'")[0].split("\\")[0]
        if u not in mp4_list:
            mp4_list.append(u)
    for idx, u in enumerate(RE_VTT_URLS.findall(unescaped)):
        u = u.split('"')[0].split("'")[0].split("\\")[0]
        lm = re.search(r'[/_-]([a-z]{2})\.vtt', u, re.IGNORECASE)
        code = lm.group(1).upper() if lm else f"SUB-{idx+1}"
        if not any(s["url"] == u for s in subtitles):
            subtitles.append({"lang": code, "label": f"Subtitle ({code})", "url": u})

    for mp4 in mp4_list:
        if any(k in mp4.lower() for k in ["preview", "trailer", "thumb"]):
            preview_mp4 = mp4
            break
    if not preview_mp4 and mp4_list:
        preview_mp4 = mp4_list[0]

    qualities: List[Dict[str, Any]] = []
    master_m3u8 = ""
    if m3u8_list:
        master_m3u8 = m3u8_list[0]
        parsed = await parse_master_playlist(master_m3u8, duration_sec, headers)
        if parsed:
            qualities.extend(parsed)
        for u in m3u8_list:
            res = re.search(r'(2160p|1440p|1080p|720p|480p|360p|240p|4k)', u, re.IGNORECASE)
            label = res.group(1).lower() if res else "auto"
            if not any(q["url"] == u for q in qualities):
                qualities.append({
                    "quality": label, "url": u, "type": "m3u8",
                    "bandwidth": 0, "size_mb": estimate_size_mb(duration_sec, label),
                })

    for u in mp4_list:
        if u == preview_mp4 and len(mp4_list) > 1:
            continue
        res = re.search(r'(2160p|1440p|1080p|720p|480p|360p|240p|4k)', u, re.IGNORECASE)
        label = f"{res.group(1).lower()}" if res else "720p"
        qualities.append({
            "quality": label, "url": u, "type": "mp4",
            "bandwidth": 0, "size_mb": estimate_size_mb(duration_sec, label),
        })

    order = {"2160p": 1, "4k": 1, "1440p": 2, "1080p": 3, "720p": 4, "480p": 5, "360p": 6, "240p": 7}
    qualities.sort(key=lambda x: next((v for k, v in order.items() if k in x["quality"].lower()), 99))

    best = master_m3u8 if master_m3u8 else (qualities[0]["url"] if qualities else preview_mp4)

    session_id = ""
    if master_m3u8:
        session_id = mint_stream_session(master_m3u8, license_key)

    return {
        "video_url": video_url,
        "title": title,
        "studio": studio,
        "thumbnail": thumbnail,
        "duration_seconds": duration_sec,
        "duration_formatted": format_duration(duration_sec),
        "preview_url": preview_mp4,
        "auto_best_url": best,
        "master_m3u8": master_m3u8,
        "qualities": qualities,
        "subtitles": subtitles,
        "stream_session_id": session_id,
        "dom_injection_css": "",
    }

# ==============================================================================
# 8. ENDPOINTS
# ==============================================================================
@app.get("/ping")
@app.head("/ping")
async def ping():
    return {"status": "alive", "ts": int(time.time())}


@app.post("/api/v1/sec/init")
async def init_endpoint(request: Request):
    envelope = await request.json()
    payload = decrypt_and_verify_payload(envelope)
    device_id = payload.get("device_id", "unknown")

    if await verify_integrity(payload, device_id):
        return encrypt_and_sign_response({
            "success": True, "code": "OK", "shadow": True,
            "update": {"enabled": False},
        })

    return encrypt_and_sign_response({
        "success": True, "code": "OK",
        "update": MEM_STATE["update_config"],
        "server_time": int(time.time()),
    })


@app.post("/api/v1/sec/license/verify")
async def license_verify_endpoint(request: Request):
    envelope = await request.json()
    payload = decrypt_and_verify_payload(envelope)

    license_key = str(payload.get("license_key", "")).strip()
    device_id = str(payload.get("device_id", "")).strip()
    device_name = str(payload.get("device_name", "Android")).strip()
    app_version = str(payload.get("app_version", EXPECTED_VERSION_NAME)).strip()
    is_heartbeat = bool(payload.get("is_heartbeat", False))
    client_ip = request.client.host if request.client else "0.0.0.0"

    if not device_id or len(device_id) < 8:
        return encrypt_and_sign_response({
            "success": False, "code": "INVALID_DEVICE",
            "message": "Invalid DRM identifier.",
        })

    block = check_device_blocked(device_id)
    if block:
        return encrypt_and_sign_response({
            "success": False, "code": "USER_BLOCKED_24H",
            "blocked_until_remaining": block["remaining_seconds"],
            "message": block["message"],
            "purchase_text": "Purchase from Telegram starting from ₹9/day.",
            "telegram_url": "https://t.me/drdevstudio",
            "bot_url": "https://t.me/drdevbot",
        })

    is_shadow = await verify_integrity(payload, device_id)
    provider_res = await verify_license(license_key, device_id, device_name, app_version)
    http_status = provider_res.get("http_status", 500)
    success = bool(provider_res.get("success", False))
    code = provider_res.get("code", "UNKNOWN_ERROR")

    if http_status == 200 and success and code == "OK":
        if device_id in MEM_STATE["blocked_users"]:
            MEM_STATE["blocked_users"].pop(device_id, None)
            await sync_node_to_firebase("blocked_users", device_id, None)
        lic = provider_res.get("license", {})
        user = lic.get("user", {})
        record = {
            "key": license_key,
            "full_name": user.get("full_name", "Premium User"),
            "status": "shadow_banned" if is_shadow else lic.get("status", "active"),
            "plan": lic.get("plan", "Premium"),
            "expires_at": lic.get("expires_at", 0),
            "remaining_seconds": lic.get("remaining_seconds", 0),
            "device_id": device_id,
            "device_name": device_name,
            "last_verified": int(time.time()),
        }
        MEM_STATE["licenses"][license_key] = record
        await sync_node_to_firebase("licenses", license_key, record)
        return encrypt_and_sign_response({
            "success": True, "code": "OK", "message": "License valid.",
            "server_time": provider_res.get("server_time", int(time.time())),
            "license": lic,
            "update": MEM_STATE["update_config"],
        })

    if code == "LICENSE_EXPIRED":
        if license_key in MEM_STATE["licenses"]:
            MEM_STATE["licenses"][license_key]["status"] = "expired"
            await sync_node_to_firebase("licenses", license_key, MEM_STATE["licenses"][license_key])
        return encrypt_and_sign_response({
            "success": False, "code": "LICENSE_EXPIRED",
            "message": "License expired.",
            "expired_at": provider_res.get("expired_at", 0),
            "bot_url": "https://t.me/drdevbot",
            "telegram_url": "https://t.me/drdevstudio",
        })

    if not is_heartbeat and code in ("LICENSE_NOT_FOUND", "LICENSE_REVOKED", "DEVICE_MISMATCH"):
        attempt = await record_failed_attempt(device_id, client_ip)
        tries_left = max(0, 3 - attempt["failed_attempts"])
        if tries_left == 0:
            return encrypt_and_sign_response({
                "success": False, "code": "USER_BLOCKED_24H",
                "message": "3 failed attempts. Blocked 24 hours.",
                "bot_url": "https://t.me/drdevbot",
                "telegram_url": "https://t.me/drdevstudio",
            })
        return encrypt_and_sign_response({
            "success": False, "code": code,
            "tries_left": tries_left,
            "message": f"{provider_res.get('message', 'Invalid.')} ({tries_left} remaining).",
            "bot_url": "https://t.me/drdevbot",
            "telegram_url": "https://t.me/drdevstudio",
        })

    return encrypt_and_sign_response({
        "success": False, "code": code,
        "message": provider_res.get("message", "Verification failed."),
        "retry_after": provider_res.get("retry_after", 30),
        "bot_url": "https://t.me/drdevbot",
        "telegram_url": "https://t.me/drdevstudio",
    })


@app.post("/api/v1/sec/video/fetch")
async def fetch_video_endpoint(request: Request):
    envelope = await request.json()
    payload = decrypt_and_verify_payload(envelope)

    license_key = str(payload.get("license_key", "")).strip()
    device_id = str(payload.get("device_id", "")).strip()
    device_name = str(payload.get("device_name", "Android")).strip()
    app_version = str(payload.get("app_version", EXPECTED_VERSION_NAME)).strip()
    video_url = str(payload.get("video_url", "")).strip()

    if not license_key or not video_url:
        return encrypt_and_sign_response({
            "success": False, "code": "INVALID_REQUEST",
            "message": "Missing license or URL.",
        })

    now = int(time.time())
    rl = MEM_STATE["rate_limits"].get(license_key, {
        "key": license_key, "window_start": now, "count": 0, "rate_limited_until": 0,
    })
    if rl.get("rate_limited_until", 0) > now:
        rem = rl["rate_limited_until"] - now
        return encrypt_and_sign_response({
            "success": False, "code": "VIDEO_RATE_LIMITED_1H",
            "retry_after": rem,
            "message": f"Rate limit. Wait {rem // 60}m {rem % 60}s.",
        })
    if now - rl.get("window_start", now) >= 60:
        rl["window_start"] = now
        rl["count"] = 1
        rl["rate_limited_until"] = 0
    else:
        rl["count"] = rl.get("count", 0) + 1
        if rl["count"] > 20:
            rl["rate_limited_until"] = now + 3600
            MEM_STATE["rate_limits"][license_key] = rl
            await sync_node_to_firebase("rate_limits", license_key, rl)
            return encrypt_and_sign_response({
                "success": False, "code": "VIDEO_RATE_LIMITED_1H",
                "retry_after": 3600,
                "message": "20 videos/min exceeded. 1h lock.",
            })
    MEM_STATE["rate_limits"][license_key] = rl
    await sync_node_to_firebase("rate_limits", license_key, rl)

    lic = MEM_STATE["licenses"].get(license_key)
    if not lic or (now - lic.get("last_verified", 0) > 180):
        prov = await verify_license(license_key, device_id, device_name, app_version)
        if not (prov.get("http_status") == 200 and prov.get("success") and prov.get("code") == "OK"):
            code = prov.get("code", "LICENSE_INVALID")
            return encrypt_and_sign_response({
                "success": False, "code": code,
                "message": "License expired." if code == "LICENSE_EXPIRED" else prov.get("message", "License invalid."),
                "bot_url": "https://t.me/drdevbot",
                "telegram_url": "https://t.me/drdevstudio",
            })
        lic_obj = prov.get("license", {})
        lic = {
            "key": license_key,
            "full_name": lic_obj.get("user", {}).get("full_name", "Premium User"),
            "status": lic_obj.get("status", "active"),
            "plan": lic_obj.get("plan", "30 days"),
            "expires_at": lic_obj.get("expires_at", 0),
            "remaining_seconds": lic_obj.get("remaining_seconds", 0),
            "device_id": device_id,
            "device_name": device_name,
            "last_verified": now,
        }
        MEM_STATE["licenses"][license_key] = lic
        await sync_node_to_firebase("licenses", license_key, lic)
    else:
        if lic.get("expires_at", 0) <= now:
            return encrypt_and_sign_response({
                "success": False, "code": "LICENSE_EXPIRED",
                "message": "License expired.",
                "bot_url": "https://t.me/drdevbot",
            })

    if await verify_integrity(payload, device_id):
        return encrypt_and_sign_response({
            "success": True, "code": "OK",
            "video": {
                "video_url": video_url, "title": "Loading...", "studio": "FapHouse",
                "thumbnail": "", "duration_seconds": 0, "duration_formatted": "00:00",
                "preview_url": "https://127.0.0.1/trap.mp4",
                "auto_best_url": "https://127.0.0.1/trap.m3u8",
                "master_m3u8": "https://127.0.0.1/trap.m3u8",
                "qualities": [], "subtitles": [],
                "stream_session_id": "shadow_trap",
                "dom_injection_css": "",
            },
        })

    try:
        data = await fetch_premium_video_data(video_url, license_key)
        return encrypt_and_sign_response({
            "success": True, "code": "OK", "video": data,
        })
    except Exception as e:
        return encrypt_and_sign_response({
            "success": False, "code": "FETCH_ERROR",
            "message": f"Fetch failed: {str(e)}",
        })

# ==============================================================================
# 9. HLS STREAM PROXY
# ==============================================================================
def _stream_headers() -> Dict[str, str]:
    return {
        "User-Agent": UPSTREAM_UA,
        "Accept": "*/*",
        "Accept-Language": "en-IN,en-GB;q=0.9,en;q=0.8",
        "Referer": "https://faphouse2.com/",
        "Origin": "https://faphouse2.com",
        "Cookie": MEM_STATE.get("premium_cookies", PREMIUM_COOKIES),
    }


@app.api_route("/api/v1/stream/{session_id}/{path_kind:path}", methods=["GET", "HEAD"])
async def stream_proxy(session_id: str, path_kind: str, request: Request):
    sess = STREAM_SESSIONS.get(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Stream session expired")
    if int(time.time()) - sess.get("created", 0) > STREAM_SESSION_TTL:
        STREAM_SESSIONS.pop(session_id, None)
        raise HTTPException(status_code=404, detail="Stream session expired")
    sess["last_used"] = int(time.time())

    if not http_client:
        raise HTTPException(status_code=503, detail="Backend not ready")

    upstream_url = ""
    is_playlist = False
    base_for_rewrite = ""

    if path_kind == "master.m3u8":
        upstream_url = sess["master_url"]
        base_for_rewrite = upstream_url.rsplit("/", 1)[0] + "/"
        is_playlist = True
    elif path_kind.startswith("var/"):
        try:
            upstream_url = b64url_dec(path_kind[4:])
        except Exception:
            raise HTTPException(status_code=400, detail="Bad var token")
        base_for_rewrite = upstream_url.rsplit("/", 1)[0] + "/"
        is_playlist = True
    elif path_kind.startswith("seg/"):
        try:
            upstream_url = b64url_dec(path_kind[4:])
        except Exception:
            raise HTTPException(status_code=400, detail="Bad seg token")
        is_playlist = False
    elif path_kind.startswith("key/"):
        try:
            upstream_url = b64url_dec(path_kind[4:])
        except Exception:
            raise HTTPException(status_code=400, detail="Bad key token")
        is_playlist = False
    else:
        raise HTTPException(status_code=400, detail="Bad stream path")

    if not is_allowed_upstream(upstream_url):
        raise HTTPException(status_code=403, detail="Upstream domain not allowed")

    req_headers = _stream_headers()
    incoming_range = request.headers.get("range")
    if incoming_range:
        req_headers["Range"] = incoming_range

    if is_playlist:
        try:
            r = await http_client.get(upstream_url, headers=req_headers)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Upstream error: {e}")
        if r.status_code != 200:
            raise HTTPException(status_code=r.status_code, detail="Upstream returned error")
        rewritten = rewrite_playlist(r.text, base_for_rewrite, session_id)
        return Response(
            content=rewritten,
            media_type="application/vnd.apple.mpegurl",
            headers={
                "Cache-Control": "no-cache, no-store",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "*",
            },
        )

    media_type = guess_content_type(upstream_url)

    async def iter_upstream():
        try:
            async with http_client.stream("GET", upstream_url, headers=req_headers) as upstream:
                if upstream.status_code not in (200, 206):
                    return
                async for chunk in upstream.aiter_raw(65536):
                    yield chunk
        except Exception:
            return

    out_headers = {
        "Cache-Control": "public, max-age=300",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Accept-Ranges": "bytes",
    }
    return StreamingResponse(
        iter_upstream(),
        media_type=media_type,
        headers=out_headers,
        status_code=200,
    )

# ==============================================================================
# 10. ADMIN
# ==============================================================================
@app.get("/admin", response_class=HTMLResponse)
async def admin_panel_view(request: Request, token: Optional[str] = None):
    await sync_from_firebase()
    now = int(time.time())
    licenses_list = list(MEM_STATE["licenses"].values())
    active = [l for l in licenses_list if l.get("status") == "active" and l.get("expires_at", 0) > now]
    expired = [l for l in licenses_list if l.get("status") == "expired" or (0 < l.get("expires_at", 0) <= now)]
    blocked = [b for b in MEM_STATE["blocked_users"].values() if b.get("blocked_until", 0) > now]
    rate_limited = [r for r in MEM_STATE["rate_limits"].values() if r.get("rate_limited_until", 0) > now]
    shadow = list(MEM_STATE["shadow_banned"].values())

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "authorized": (token == ADMIN_SECRET_TOKEN),
            "token": token or "",
            "stats": {
                "active_count": len(active),
                "expired_count": len(expired),
                "blocked_count": len(blocked),
                "rate_limited_count": len(rate_limited),
                "shadow_banned_count": len(shadow),
            },
            "licenses": licenses_list,
            "blocked_users": blocked,
            "rate_limited_users": rate_limited,
            "shadow_banned_users": shadow,
            "update_config": MEM_STATE["update_config"],
            "premium_cookies": MEM_STATE.get("premium_cookies", ""),
            "now": now,
        }
    )




@app.post("/admin/action")
async def admin_panel_action(
    token: str = Form(...),
    action_type: str = Form(...),
    target_key: str = Form(""),
    update_enabled: Optional[str] = Form(None),
    version_name: str = Form("1.0.0"),
    version_code: int = Form(1),
    features: str = Form(""),
    update_url: str = Form(""),
    premium_cookies: str = Form(""),
):
    if token != ADMIN_SECRET_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if action_type == "update_config":
        cfg = {
            "enabled": update_enabled == "on",
            "version_name": version_name.strip(),
            "version_code": int(version_code),
            "features": features.strip(),
            "update_url": update_url.strip(),
            "force_update": True,
        }
        MEM_STATE["update_config"] = cfg
        await sync_node_to_firebase("update_config", None, cfg)
    elif action_type == "update_cookies":
        MEM_STATE["premium_cookies"] = premium_cookies.strip()
        await sync_node_to_firebase("premium_cookies", None, MEM_STATE["premium_cookies"])
    elif action_type == "unblock_device" and target_key:
        MEM_STATE["blocked_users"].pop(target_key, None)
        await sync_node_to_firebase("blocked_users", target_key, None)
    elif action_type == "clear_ratelimit" and target_key:
        MEM_STATE["rate_limits"].pop(target_key, None)
        await sync_node_to_firebase("rate_limits", target_key, None)
    elif action_type == "remove_shadowban" and target_key:
        MEM_STATE["shadow_banned"].pop(target_key, None)
        await sync_node_to_firebase("shadow_banned", target_key, None)
    return RedirectResponse(url=f"/admin?token={token}", status_code=303)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), workers=1)
