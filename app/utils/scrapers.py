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
            intel_data = await page.evaluate("""() => {
                const results = [];
                // FortiGuard uses div.row[role="button"] for results
                const items = document.querySelectorAll('div.row[role="button"]');
                
                items.forEach(item => {
                    const categoryEl = item.querySelector('div.col-md-3 small');
                    const valueEl = item.querySelector('div.col-md-3 b') || item.querySelector('div.col-md-3 small'); // Might be domain or IP
                    const detailsEl = item.querySelector('div.col-md-9 small');
                    
                    if (categoryEl && detailsEl) {
                        results.push({ 
                            type: categoryEl.innerText.trim(), 
                            value: valueEl ? valueEl.innerText.trim() : 'N/A', 
                            details: detailsEl.innerText.trim() 
                        });
                    }
                });

                // Heuristic for Reputation
                let reputation = "Clean";
                const bodyText = document.body.innerText;
                const bodyHtml = document.body.innerHTML;
                
                // Better heuristic: look for specific red/green markers or explicit keywords
                const maliciousKeywords = ['Malicious Websites', 'Phishing', 'Spam', 'C&C', 'Botnet', 'Malware', 'Blocklist'];
                const suspiciousKeywords = ['Suspicious', 'Unrated', 'Newly Observed', 'Proxy-Avoidance', 'Tor-Relay'];
                
                // Check if any malicious keyword appears in the first 5000 chars of body text
                // excluding generic mentions
                const firstSection = bodyText.substring(0, 5000);
                
                let isMalicious = maliciousKeywords.some(mw => firstSection.includes(mw));
                let isSuspicious = suspiciousKeywords.some(sw => firstSection.includes(sw));

                if (isMalicious) {
                    reputation = "Malicious";
                } else if (isSuspicious) {
                    reputation = "Suspicious";
                } else if (bodyText.includes('Safe') || bodyText.includes('Clean')) {
                    reputation = "Clean";
                }

                // Look for categorization from the first result if available
                let category = "N/A";
                // Try to find "Category:" in the text
                const catMatch = bodyText.match(/Category[:\\s]+([^<\\n\\r]+)/i);
                if (catMatch) category = catMatch[1].trim();
                else if (results.length > 0) category = results[0].type;
                
                // Look for ISP/Owner/Organization
                let owner = "N/A";
                const ownerSelectors = [
                    /Organization[:\\s]+([^<\\n\\r]+)/i,
                    /ISP[:\\s]+([^<\\n\\r]+)/i,
                    /Owner[:\\s]+([^<\\n\\r]+)/i
                ];
                for (const reg of ownerSelectors) {
                    const m = bodyText.match(reg);
                    if (m) { owner = m[1].trim(); break; }
                }

                return {
                    reputation: reputation,
                    category: category,
                    owner: owner,
                    results: results.slice(0, 5)
                };
            }""")
            
            await browser.close()
            return {**intel_data, 'success': True, 'url': url}
            
        except Exception as e:
            return {'success': False, 'error': str(e), 'url': url}
