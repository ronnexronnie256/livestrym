"""
Livestrym Scanner
Monitors YouTube for unauthorized rebroadcasts of protected channels.
Runs as a standalone worker — no GUI, no desktop dependencies.
Designed to run 24/7 on Railway (Linux).
"""

import os
import time
import logging
import requests
import subprocess
import tempfile
import shutil
from datetime import datetime, timezone
from dotenv import load_dotenv
from googleapiclient.discovery import build

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
YOUTUBE_API_KEY    = os.getenv("YOUTUBE_API_KEY")
CHANNEL_ID         = os.getenv("PHANEROO_CHANNEL_ID", "UCrEG2rXLpLVSZJntGuHV8fw")
TELEGRAM_TOKEN     = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")
SCAN_INTERVAL      = int(os.getenv("SCAN_INTERVAL", "60"))
SAMPLE_DURATION    = 45
MATCH_THRESHOLD    = 0.70

KEYWORDS = [
    "Phaneroo",
    "Phaneroo Ministries",
    "Phaneroo Service",
    "Apostle Grace Lubega",
    "Phaneroo Sunday Service",
]

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger("livestrym")


# ── YouTube ───────────────────────────────────────────────────────────────────

def get_youtube():
    return build("youtube", "v3", developerKey=YOUTUBE_API_KEY)


def get_my_live_stream(yt) -> dict | None:
    """Check if the protected channel is currently live."""
    try:
        r = yt.search().list(
            part="snippet",
            channelId=CHANNEL_ID,
            eventType="live",
            type="video",
            maxResults=1,
        ).execute()
        items = r.get("items", [])
        if not items:
            return None
        item = items[0]
        return {
            "video_id": item["id"]["videoId"],
            "url": f"https://www.youtube.com/watch?v={item['id']['videoId']}",
            "title": item["snippet"]["title"],
        }
    except Exception as e:
        log.error(f"Error checking live status: {e}")
        return None


def get_suspicious_streams(yt, exclude_id: str) -> list[dict]:
    """Find other channels streaming with our keywords."""
    found = {}
    for keyword in KEYWORDS:
        try:
            r = yt.search().list(
                part="snippet",
                q=keyword,
                type="video",
                eventType="live",
                maxResults=50,
                order="relevance",
            ).execute()
            for item in r.get("items", []):
                vid = item["id"].get("videoId")
                if not vid or vid == exclude_id:
                    continue
                if item["snippet"].get("channelId") == CHANNEL_ID:
                    continue
                if vid not in found:
                    sn = item["snippet"]
                    found[vid] = {
                        "video_id": vid,
                        "url": f"https://www.youtube.com/watch?v={vid}",
                        "title": sn.get("title", "")[:80],
                        "channel_title": sn.get("channelTitle", ""),
                        "channel_id": sn.get("channelId", ""),
                        "thumbnail": sn.get("thumbnails", {}).get("high", {}).get("url", ""),
                    }
            time.sleep(0.3)
        except Exception as e:
            log.error(f"Search error for '{keyword}': {e}")
    return list(found.values())


def get_viewer_count(yt, video_ids: list) -> dict:
    """Get concurrent viewer counts."""
    if not video_ids:
        return {}
    try:
        r = yt.videos().list(
            part="liveStreamingDetails",
            id=",".join(video_ids)
        ).execute()
        return {
            item["id"]: item.get("liveStreamingDetails", {}).get("concurrentViewers", "?")
            for item in r.get("items", [])
        }
    except Exception:
        return {}


# ── Stream Sampling ───────────────────────────────────────────────────────────

def get_stream_url(stream_url: str) -> str | None:
    """Get the actual HLS/DASH URL from a YouTube stream."""
    ffmpeg_path = shutil.which("ffmpeg") or "ffmpeg"
    try:
        result = subprocess.run([
            "yt-dlp",
            "--no-playlist", "--quiet", "--no-warnings",
            "--ffmpeg-location", ffmpeg_path,
            "-f", "best[height<=480]/best",
            "--get-url",
            stream_url,
        ], capture_output=True, timeout=30, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")[0]
        return None
    except Exception as e:
        log.warning(f"yt-dlp error: {e}")
        return None


def download_sample(stream_url: str, duration: int = SAMPLE_DURATION) -> str | None:
    """Download N seconds from a live stream using ffmpeg directly."""
    ffmpeg_path = shutil.which("ffmpeg") or "ffmpeg"
    actual_url  = get_stream_url(stream_url)
    if not actual_url:
        log.warning(f"Could not get stream URL for {stream_url}")
        return None

    tmp = tempfile.mktemp(suffix=".mp4")
    try:
        result = subprocess.run([
            ffmpeg_path, "-y", "-loglevel", "error",
            "-t", str(duration),
            "-i", actual_url,
            "-c", "copy", tmp,
        ], capture_output=True, timeout=duration + 30)

        if os.path.exists(tmp) and os.path.getsize(tmp) > 5000:
            log.info(f"  Sample: {os.path.getsize(tmp) // 1024}KB")
            return tmp
        if os.path.exists(tmp):
            os.unlink(tmp)
        return None
    except subprocess.TimeoutExpired:
        log.warning("ffmpeg download timed out")
        if os.path.exists(tmp):
            try: os.unlink(tmp)
            except: pass
        return None
    except Exception as e:
        log.warning(f"ffmpeg error: {e}")
        return None


# ── Fingerprinting ────────────────────────────────────────────────────────────

def fingerprint(video_path: str) -> dict:
    """Extract audio and visual fingerprints from a video clip."""
    import numpy as np
    import imagehash
    import librosa
    from PIL import Image
    from pathlib import Path
    import hashlib

    result = {"visual": [], "audio": []}

    # Visual frames
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "f_%04d.jpg")
        r = subprocess.run([
            "ffmpeg", "-i", video_path,
            "-vf", "fps=1/5", "-q:v", "2",
            out, "-y", "-loglevel", "error"
        ], capture_output=True, timeout=60)
        if r.returncode == 0:
            for fp in sorted(Path(tmp).glob("f_*.jpg")):
                try:
                    img = Image.open(fp).convert("RGB")
                    ph  = imagehash.phash(img, hash_size=16)
                    dh  = imagehash.dhash(img, hash_size=16)
                    result["visual"].append(f"{ph}:{dh}")
                except Exception:
                    pass

    # Audio
    with tempfile.TemporaryDirectory() as tmp:
        wav = os.path.join(tmp, "audio.wav")
        r = subprocess.run([
            "ffmpeg", "-i", video_path,
            "-ac", "1", "-ar", "22050",
            wav, "-y", "-loglevel", "error"
        ], capture_output=True, timeout=60)
        if r.returncode == 0 and os.path.exists(wav):
            try:
                y, sr = librosa.load(wav, sr=22050, mono=True)
                seg    = int(4 * sr)
                for i in range(max(1, len(y) // seg)):
                    chunk = y[i * seg: min((i + 1) * seg, len(y))]
                    if len(chunk) < sr:
                        continue
                    chroma = librosa.feature.chroma_cqt(y=chunk, sr=sr)
                    mfcc   = librosa.feature.mfcc(y=chunk, sr=sr, n_mfcc=13)
                    vec    = np.concatenate([
                        np.mean(chroma, axis=1),
                        np.std(chroma, axis=1),
                        np.mean(mfcc, axis=1),
                    ])
                    fp = hashlib.sha256(vec.astype(np.float32).tobytes()).hexdigest()[:32]
                    result["audio"].append(fp)
            except Exception as e:
                log.warning(f"Audio fingerprint error: {e}")

    log.info(f"  Fingerprints: {len(result['visual'])} visual, {len(result['audio'])} audio")
    return result


def compare(ref: dict, suspect: dict) -> float:
    """Compare two fingerprint sets. Returns 0.0 to 1.0."""
    import imagehash

    # Visual score
    v_score = 0.0
    if ref["visual"] and suspect["visual"]:
        matches = 0
        for ha in ref["visual"]:
            pa, da = ha.split(":")
            ph_a   = imagehash.hex_to_hash(pa)
            dh_a   = imagehash.hex_to_hash(da)
            for hb in suspect["visual"]:
                pb, db = hb.split(":")
                if (ph_a - imagehash.hex_to_hash(pb)) <= 12 and \
                   (dh_a - imagehash.hex_to_hash(db)) <= 12:
                    matches += 1
                    break
        v_score = matches / len(ref["visual"])

    # Audio score
    a_score = 0.0
    if ref["audio"] and suspect["audio"]:
        s = set(suspect["audio"])
        a_score = sum(1 for fp in ref["audio"] if fp in s) / len(ref["audio"])

    combined = (v_score * 0.35) + (a_score * 0.65)
    log.info(f"  Score: visual={v_score:.0%} audio={a_score:.0%} combined={combined:.0%}")
    return combined


# ── Telegram ──────────────────────────────────────────────────────────────────

def send_telegram(match: dict):
    """Send a Telegram alert for a detected rebroadcast."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        log.warning("Telegram not configured")
        return

    score    = match["combined_score"]
    bar      = "█" * round(score * 10) + "░" * (10 - round(score * 10))
    viewers  = match.get("concurrent_viewers", "?")
    time_str = datetime.now(timezone.utc).strftime("%H:%M UTC")

    text = (
        f"*Livestrym — Rebroadcast Detected*\n\n"
        f"Stream: {match.get('title', '')[:60]}\n"
        f"Link: {match['url']}\n"
        f"Channel: {match['channel_title']}\n"
        f"Viewers: {viewers}\n\n"
        f"Confidence: {bar} {score:.0%}\n"
        f"Detected: {time_str}"
    )

    # Send thumbnail if available
    if match.get("thumbnail"):
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendPhoto",
                json={"chat_id": TELEGRAM_CHAT_ID, "photo": match["thumbnail"],
                      "caption": f"Rebroadcast: {match.get('title', '')[:100]}"},
                timeout=10
            )
        except Exception:
            pass

    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"},
            timeout=10
        )
        if r.status_code == 200:
            log.info("Telegram alert sent")
        else:
            log.error(f"Telegram error: {r.text}")
    except Exception as e:
        log.error(f"Telegram failed: {e}")

def log_detection_to_api(match: dict):
    """Log a confirmed rebroadcast to the Livestrym API."""
    api_url = os.getenv("API_URL", "http://localhost:8000")
    try:
        r = requests.post(
            f"{api_url}/api/detections",
            json={
                "stream_url":         match.get("url", ""),
                "stream_title":       match.get("title", ""),
                "channel_name":       match.get("channel_title", ""),
                "channel_id":         match.get("channel_id", ""),
                "thumbnail_url":      match.get("thumbnail", ""),
                "concurrent_viewers": str(match.get("concurrent_viewers", "?")),
                "confidence_score":   str(match.get("combined_score", 0)),
            },
            timeout=10
        )
        if r.status_code == 200:
            log.info("Detection logged to API")
        else:
            log.warning(f"API log failed: {r.status_code}")
    except Exception as e:
        log.warning(f"Could not log to API: {e}")
# ── Main Loop ─────────────────────────────────────────────────────────────────

def run():
    log.info("=" * 50)
    log.info("Livestrym Scanner started")
    log.info(f"Monitoring channel: {CHANNEL_ID}")
    log.info(f"Scan interval: {SCAN_INTERVAL}s")
    log.info("=" * 50)

    yt               = get_youtube()
    already_reported = set()
    live_start_time  = None
    scan_count       = 0

    while True:
        try:
            # Check if protected channel is live
            my_stream = get_my_live_stream(yt)

            if not my_stream:
                if live_start_time is not None:
                    log.info("Stream ended. Resetting session.")
                    live_start_time  = None
                    already_reported = set()
                log.info(f"Channel offline. Next check in {SCAN_INTERVAL}s...")
                time.sleep(SCAN_INTERVAL)
                continue

            # Channel is live
            if live_start_time is None:
                live_start_time = datetime.now(timezone.utc)
                title = my_stream['title'].encode('ascii', 'ignore').decode()
                log.info(f"LIVE: {title}")
                log.info(f"URL: {my_stream['url']}")

            minutes_live = (datetime.now(timezone.utc) - live_start_time).seconds // 60
            interval     = SCAN_INTERVAL if minutes_live < 30 else SCAN_INTERVAL * 2

            # Sample the reference stream
            log.info("Sampling reference stream...")
            ref_path = download_sample(my_stream["url"])
            if not ref_path:
                log.warning("Could not sample reference. Retrying in 30s...")
                time.sleep(30)
                continue

            ref_fp = fingerprint(ref_path)
            os.unlink(ref_path)

            if not ref_fp["audio"] and not ref_fp["visual"]:
                log.warning("No fingerprints from reference. Retrying in 30s...")
                time.sleep(30)
                continue

            # Find and check suspicious streams
            suspects = get_suspicious_streams(yt, my_stream["video_id"])
            scan_count += 1
            log.info(f"Scan #{scan_count}: {len(suspects)} suspects | {minutes_live}m live")

            # Get viewer counts
            viewer_counts = get_viewer_count(yt, [s["video_id"] for s in suspects])
            for s in suspects:
                s["concurrent_viewers"] = viewer_counts.get(s["video_id"], "?")

            for suspect in suspects:
                if suspect["channel_id"] in already_reported:
                    continue

                log.info(f"Checking: {suspect['channel_title']} — {suspect['title'][:40]}")
                sus_path = download_sample(suspect["url"])
                if not sus_path:
                    continue

                sus_fp = fingerprint(sus_path)
                os.unlink(sus_path)

                score = compare(ref_fp, sus_fp)
                if score >= MATCH_THRESHOLD:
                    log.info(f"MATCH: {suspect['channel_title']} at {score:.0%}")
                    suspect["combined_score"] = score
                    send_telegram(suspect)
                    log_detection_to_api(suspect)
                    already_reported.add(suspect["channel_id"])

            log.info(f"Next scan in {interval}s...")
            time.sleep(interval)

        except KeyboardInterrupt:
            log.info("Scanner stopped.")
            break
        except Exception as e:
            log.error(f"Scanner error: {e}. Restarting in 60s...")
            time.sleep(60)


if __name__ == "__main__":
    run()