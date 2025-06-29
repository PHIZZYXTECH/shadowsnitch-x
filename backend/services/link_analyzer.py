import aiohttp

async def analyze_url(url: str):
    result = {
        "url": url,
        "redirect_chain": [],
        "final_url": None
    }

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                result["final_url"] = str(resp.url)
                result["redirect_chain"] = [str(h.url) for h in resp.history]
        except Exception as e:
            result["error"] = str(e)

    return result
