import requests
from bs4 import BeautifulSoup
import re

def fetch_url_metadata(url):
    """Fetch title and summary from a given URL."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'lxml')
        title = soup.title.string.strip() if soup.title else "Untitled Source"
        
        # Try to find a good summary
        summary = ""
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc:
            summary = meta_desc.get('content', '').strip()
        
        if not summary:
            # Fallback: take first paragraph
            p = soup.find('p')
            if p:
                summary = p.get_text().strip()[:300]
        
        return {
            'title': title[:300],
            'summary': summary[:1000],
            'url': url
        }
    except Exception as e:
        print(f"DEBUG: Scraper Error: {e}")
        return None

def calculate_relevance(text):
    """
    Calculate a security relevance score based on keywords.
    Returns: (score, is_relevant)
    """
    if not text:
        return 0, False
        
    keywords = [
        'cve', 'vulnerability', 'exploit', 'hacker', 'patch', 'zero-day', 
        'malware', 'ransomware', 'breach', 'leak', 'security', 'cyber', 
        'attack', 'threat', 'poc', 'denial', 'injection', 'xss', 'sqli',
        'bypass', 'backdoor', 'spyware', 'phishing', 'rce', 'critical',
        'high risk', 'patched', 'fix', 'buffer overflow', 'stored xss'
    ]
    
    text_lower = text.lower()
    score = 0
    matches = []
    
    for word in keywords:
        pattern = r'\b' + re.escape(word) + r'\b'
        found = re.findall(pattern, text_lower)
        if found:
            score += len(found) * 5
            matches.append(word)
            
    # Bonus for CVE patterns
    cve_pattern = r'cve-\d{4}-\d+'
    cves = re.findall(cve_pattern, text_lower)
    if cves:
        score += len(cves) * 20
        
    is_relevant = score >= 15 # Threshold
    return score, is_relevant

async def fetch_fortiguard_threat_intel(indicator):
    """
    Fetch threat intelligence from FortiGuard Labs.
    Uses Playwright to handle dynamic content and bypass anti-bot measures.
    """
    from playwright.async_api import async_playwright
    from playwright_stealth import Stealth
    import asyncio
    
    # URL construction
    url = f"https://www.fortiguard.com/threatintel-search?q={indicator}"
    
    async with async_playwright() as p:
        try:
            # Launch browser
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={'width': 1280, 'height': 800},
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            )
            
            # Create page and apply stealth
            page = await context.new_page()
            stealth = Stealth()
            await stealth.apply_stealth_async(page)
            
            # Navigate to FortiGuard
            await page.goto(url, wait_until='domcontentloaded', timeout=20000)
            
            # Wait for content to stabilize
            await page.wait_for_timeout(3000)
            
            # Extract data
            intel_data = await page.evaluate(r"""() => {
                const results = [];
                // More aggressive row detection
                const potentialRows = [...document.querySelectorAll('div')].filter(el => 
                    el.innerText && el.innerText.length > 5 && el.innerText.length < 500 &&
                    (el.innerText.includes('found as') || el.innerText.includes('located on') || el.innerText.includes('blocklist'))
                );
                
                potentialRows.forEach(row => {
                    // Try to find a header and a value
                    const text = row.innerText.trim();
                    const parts = text.split(/\n/);
                    if (parts.length >= 2) {
                        results.push({
                            type: parts[0].trim(),
                            details: parts.slice(1).join(' ').trim()
                        });
                    } else {
                        results.push({
                            type: 'Intelligence',
                            details: text
                        });
                    }
                });

                const bodyText = document.body.innerText;
                
                // Reputation Heuristic
                let reputation = "Clean";
                const maliciousMarkers = ['blocklist', 'Malicious', 'Phishing', 'Spam', 'C&C', 'Botnet', 'Malware', 'Blocklist', 'High Risk'];
                const suspiciousMarkers = ['Suspicious', 'Unrated', 'Newly Observed', 'Proxy-Avoidance', 'Tor', 'VPN'];
                
                let isMalicious = maliciousMarkers.some(m => bodyText.includes(m));
                let isSuspicious = suspiciousMarkers.some(m => bodyText.includes(m)) || bodyText.includes('found as Tor');

                if (isMalicious) reputation = "Malicious";
                else if (isSuspicious) reputation = "Suspicious";
                else if (bodyText.includes('Safe') || bodyText.includes('Clean')) reputation = "Clean";

                // Extract Category and Organization from the results
                let category = "N/A";
                let owner = "N/A";

                results.forEach(r => {
                    // Organization/Location extraction
                    if (r.type.toLowerCase().includes('geolocation') || r.details.toLowerCase().includes('located on')) {
                        const locMatch = r.details.match(/located on ([^<\n\r]+)/i);
                        owner = locMatch ? locMatch[1].trim() : r.details;
                    }
                    
                    // Category extraction
                    if (r.details.toLowerCase().includes('found as') || r.type.toLowerCase().includes('security') || r.type.toLowerCase().includes('antispam')) {
                        if (category === "N/A") {
                            const foundMatch = r.details.match(/found as ([^<\n\r]+)/i);
                            category = foundMatch ? foundMatch[1].trim() : r.type;
                        }
                    }
                });

                // Final Pass: Search for Location info directly if not found
                if (owner === "N/A") {
                    const geoMatch = bodyText.match(/The IP is located on ([^<\n\r]+)/i);
                    if (geoMatch) owner = geoMatch[1].trim();
                }

                return {
                    reputation: reputation,
                    category: category,
                    owner: owner,
                    results: results.slice(0, 10)
                };
            }""")
            
            await browser.close()
            return {**intel_data, 'success': True, 'url': url}
            
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}
