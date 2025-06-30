from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx, socket, time
from urllib.parse import urlparse
import tldextract
import whois
import json
import random

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LinkInput(BaseModel):
    url: str

scan_results = []

@app.post("/analyze-link")
async def analyze_link(link: LinkInput):
    url = link.url
    timestamp = time.time()

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            response = await client.get(url)
            final_url = str(response.url)
            redirect_chain = [str(h.url) for h in response.history] + [final_url]
            phishing_score = round(random.uniform(0, 5), 2)

        domain = tldextract.extract(final_url).registered_domain
        domain_info = {}
        try:
            w = whois.whois(domain)
            domain_info = {
                "domain": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "country": w.country or "Unknown"
            }
        except:
            domain_info["error"] = "WHOIS lookup failed"

        ip = socket.gethostbyname(urlparse(final_url).hostname)
        geo_info = {}
        try:
            async with httpx.AsyncClient() as client:
                res = await client.get(f"https://ipinfo.io/{ip}/json")
                geo_data = res.json()
                geo_info = {
                    "ip": ip,
                    "city": geo_data.get("city"),
                    "country": geo_data.get("country"),
                    "org": geo_data.get("org"),
                    "asn": geo_data.get("asn", {}).get("asn") if "asn" in geo_data else None
                }
        except:
            geo_info = {"ip": ip, "city": "Unknown", "country": "Unknown", "org": "Unknown", "asn": None}

        related_domains = [f"{domain}-mirror{i}.onion" for i in range(1, 4)]
        is_clone = "login" in final_url.lower() or "verify" in final_url.lower()

        blacklist_status = "⚠️ Blacklisted" if "phish" in final_url else "✅ Clean"
        threat_tags = []
        if is_clone:
            threat_tags.append("Clone Detected")
        if blacklist_status != "✅ Clean":
            threat_tags.append("Listed in Blacklist")
        if geo_info["country"] not in ["NG", "US", "GB"]:
            threat_tags.append("Suspicious Country")
        if phishing_score >= 4:
            threat_tags.append("High Phishing Score")

        page_metadata = {}
        try:
            meta_start = response.text.lower().find("<title>")
            meta_end = response.text.lower().find("</title>")
            title = response.text[meta_start + 7:meta_end] if meta_start != -1 else "N/A"

            metas = {}
            for line in response.text.splitlines():
                if "<meta" in line:
                    name_start = line.find('name="')
                    if name_start != -1:
                        name_end = line.find('"', name_start + 6)
                        name = line[name_start + 6:name_end]
                        content_start = line.find('content="')
                        if content_start != -1:
                            content_end = line.find('"', content_start + 9)
                            content = line[content_start + 9:content_end]
                            metas[name] = content
            page_metadata = {
                "title": title,
                "meta": metas
            }
        except:
            page_metadata = {"title": "N/A", "meta": {}}

        result = {
            "original_url": url,
            "final_destination": final_url,
            "redirect_chain": redirect_chain,
            "phishing_score": phishing_score,
            "is_clone": is_clone,
            "blacklist_status": blacklist_status,
            "domain_info": domain_info,
            "geo_info": geo_info,
            "related_domains": related_domains,
            "threat_tags": threat_tags,
            "page_metadata": page_metadata,
            "timestamp": timestamp
        }

        scan_results.append(result)
        return result

    except Exception as e:
        return {"error": str(e)}


@app.post("/crawl-darkweb")
async def crawl_darkweb(link: LinkInput):
    onion_mirror = f"{tldextract.extract(link.url).domain}-dark.onion"
    verified = False
    return {
        "onion_mirror": f"🕸️ {onion_mirror} (simulated mirror)",
        "verified": verified
    }

@app.get("/recent-scans")
async def recent_scans():
    return scan_results[-10:]
