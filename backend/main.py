from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import httpx
import socket
import json
import time
from datetime import datetime
import random

app = FastAPI()

# 🔐 CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🧠 In-memory store
scan_history = []

# 📦 Request model
class LinkInput(BaseModel):
    url: str

# 🔍 Smart Onion Mirror Generator
def find_onion_mirror(url):
    try:
        domain = urlparse(url).netloc
        clean = domain.replace("www.", "").replace(".", "")
        return f"http://{clean}.onion (🕸️ simulated mirror)"
    except Exception:
        return "No mirror found"

# 🔍 WHOIS mock
def get_mock_whois(url):
    return {
        "domain": urlparse(url).netloc,
        "registrar": "NameCheap",
        "creation_date": "2012-06-14",
        "expiration_date": "2028-06-14",
        "country": "US"
    }

# 🌍 Geolocation mock
def get_geo_mock(ip):
    return {
        "ip": ip,
        "country": "Germany",
        "city": "Frankfurt",
        "org": "Hetzner Online GmbH",
        "asn": "AS24940"
    }

# 🧠 Metadata mock
def get_page_metadata(url):
    return {
        "title": "Suspicious Page Title",
        "meta": {
            "description": "Fake landing page for harvesting.",
            "keywords": "login, password, secure"
        }
    }

# 🧪 Clone & Blacklist
def clone_and_blacklist_check(url):
    return {
        "is_clone": random.choice([True, False]),
        "blacklist_status": random.choice(["Blacklisted", "Clean", "Suspicious"])
    }

# 🔎 Related domains mock
def related_domains(url):
    domain = urlparse(url).netloc
    return [f"login.{domain}", f"secure-{domain}", f"{domain}-mirror.net"]

# 🚨 Phishing score
def get_phishing_score(url):
    return random.randint(1, 5)

# 🏷️ Threat tags based on keywords
def tag_threats(url):
    tags = []
    if "login" in url or "secure" in url:
        tags.append("Credential Harvesting")
    if any(shortener in url for shortener in ["bit.ly", "tinyurl", "t.co"]):
        tags.append("Link Shortener")
    if "verify" in url:
        tags.append("Impersonation")
    if "free" in url or "giveaway" in url:
        tags.append("Scam Bait")
    return tags

# 🧠 Redirect chain
async def get_redirect_chain(url):
    chain = [url]
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            response = await client.get(url)
            for redirect in response.history:
                chain.append(str(redirect.headers.get("location", "")))
            chain.append(str(response.url))
    except Exception:
        pass
    return list(dict.fromkeys(chain))

# 🧪 Main analysis
@app.post("/analyze-link")
async def analyze_link(link: LinkInput):
    phishing_score = get_phishing_score(link.url)
    threats = tag_threats(link.url)
    whois = get_mock_whois(link.url)
    related = related_domains(link.url)
    mirror = find_onion_mirror(link.url)
    meta = get_page_metadata(link.url)
    clone_blacklist = clone_and_blacklist_check(link.url)

    try:
        ip = socket.gethostbyname(urlparse(link.url).netloc)
    except Exception:
        ip = "0.0.0.0"

    geo = get_geo_mock(ip)
    redirect_chain = await get_redirect_chain(link.url)
    final_dest = redirect_chain[-1] if redirect_chain else link.url

    result = {
        "original_url": link.url,
        "final_destination": final_dest,
        "redirect_chain": redirect_chain,
        "phishing_score": phishing_score,
        "threat_tags": threats,
        "domain_info": whois,
        "geo_info": geo,
        "related_domains": related,
        "is_clone": clone_blacklist["is_clone"],
        "blacklist_status": clone_blacklist["blacklist_status"],
        "page_metadata": meta,
        "onion_mirror": mirror,
        "timestamp": datetime.utcnow().isoformat()
    }

    scan_history.append(result)
    if len(scan_history) > 10:
        scan_history.pop(0)

    return result

# 🧾 Public history
@app.get("/recent-scans")
async def recent_scans():
    return scan_history[-10:]

# 🕷️ Dark Web button route
@app.post("/crawl-darkweb")
async def crawl_dark_web(link: LinkInput):
    mirror = find_onion_mirror(link.url)
    return {"onion_mirror": mirror}
