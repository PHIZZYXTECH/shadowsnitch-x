from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import httpx
import socket
import json
import hashlib
import random

app = FastAPI()

# Allow frontend to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store scans in memory for public history mode
scan_history = []

class URLRequest(BaseModel):
    url: str

def mock_whois(domain):
    return {
        "domain": domain,
        "registrar": "NameCheap, Inc.",
        "creation_date": "2015-06-01",
        "expiration_date": "2026-06-01",
        "country": "US"
    }

def get_redirect_chain(url):
    try:
        with httpx.Client(follow_redirects=True, timeout=10) as client:
            response = client.get(url)
            chain = [resp.url for resp in response.history] + [response.url]
            return [str(link) for link in chain]
    except Exception:
        return [url]

def generate_threat_tags(url):
    tags = []
    if any(s in url for s in ["login", "bank", "verify", "secure"]):
        tags.append("phishing")
    if "@" in url or len(url) > 100:
        tags.append("obfuscation")
    if "bit.ly" in url or "tinyurl" in url:
        tags.append("link shortener")
    if url.endswith(".zip") or url.endswith(".exe"):
        tags.append("malware")
    return tags

def mock_geo_asn(ip):
    return {
        "ip": ip,
        "city": "Amsterdam",
        "country": "Netherlands",
        "org": "DarkNet Hosting",
        "asn": "AS6666"
    }

def check_clone_or_blacklist(url):
    if "clone" in url:
        return True, "Blacklisted"
    return False, "Clean"

def mock_related_domains(domain):
    return [f"login.{domain}", f"secure-{domain}", f"{domain}-verify.com"]

def fake_metadata(url):
    return {
        "title": "Suspicious Page",
        "meta": {
            "description": "This site looks shady.",
            "generator": "WixSite Builder",
            "keywords": "earn money, hack, free bitcoin"
        }
    }

def extract_domain(url):
    try:
        return url.split("//")[-1].split("/")[0].replace("www.", "")
    except:
        return url

@app.post("/analyze-link")
async def analyze_link(request: URLRequest):
    url = request.url
    domain = extract_domain(url)
    ip = socket.gethostbyname(domain)

    redirect_chain = get_redirect_chain(url)
    final_url = redirect_chain[-1]

    phishing_score = min(len(generate_threat_tags(url)) + random.randint(0, 2), 5)
    threat_tags = generate_threat_tags(url)
    geo_info = mock_geo_asn(ip)
    whois_info = mock_whois(domain)
    is_clone, blacklist_status = check_clone_or_blacklist(url)
    related = mock_related_domains(domain)
    metadata = fake_metadata(url)

    result = {
        "original_url": url,
        "final_destination": final_url,
        "redirect_chain": redirect_chain,
        "phishing_score": phishing_score,
        "threat_tags": threat_tags,
        "domain_info": whois_info,
        "geo_info": geo_info,
        "is_clone": is_clone,
        "blacklist_status": blacklist_status,
        "related_domains": related,
        "page_metadata": metadata,
        "timestamp": datetime.now().isoformat()
    }

    scan_history.append(result)
    if len(scan_history) > 10:
        scan_history.pop(0)

    return result

@app.get("/recent-scans")
async def recent_scans():
    return scan_history[::-1]

@app.post("/crawl-darkweb")
async def crawl_darkweb(request: URLRequest):
    url = request.url
    domain = extract_domain(url)

    # Simulate Tor mirror lookup
    if any(x in url for x in ["onion", "dark", "hidden", "mirror", ".zip"]):
        mirror = f"http://{domain}.onion"
        verified = random.choice([True, False])
    else:
        mirror = "🕸️ simulated mirror"
        verified = False

    return {
        "original": url,
        "onion_mirror": mirror,
        "verified": verified,
        "timestamp": datetime.utcnow().isoformat()
    }
