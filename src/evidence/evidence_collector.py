"""
Evidence Collector for PhishTrace.
Captures screenshots, HTML, and metadata from URLs.
"""
import asyncio
import hashlib
import json
import os
from datetime import datetime
from playwright.async_api import async_playwright

class EvidenceCollector:
    def __init__(self, output_dir='evidence'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    def compute_hash(self, data):
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).hexdigest()

    async def capture(self, url, timeout=30000):
        evidence = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'artifacts': [],
            'status': 'pending'
        }
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=['--no-sandbox'])
            context = await browser.new_context(viewport={'width': 1280, 'height': 720})
            page = await context.new_page()
            try:
                await page.goto(url, timeout=timeout, wait_until='domcontentloaded')
                await page.wait_for_timeout(3000)
                
                # Screenshot
                ss_path = os.path.join(self.output_dir, f'screenshot_{self.timestamp}.png')
                await page.screenshot(path=ss_path, full_page=True)
                with open(ss_path, 'rb') as f:
                    ss_data = f.read()
                evidence['artifacts'].append({
                    'type': 'screenshot', 'path': os.path.basename(ss_path),
                    'sha256': self.compute_hash(ss_data), 'size_bytes': len(ss_data)
                })
                
                # HTML
                html_content = await page.content()
                html_path = os.path.join(self.output_dir, f'html_{self.timestamp}.html')
                with open(html_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                evidence['artifacts'].append({
                    'type': 'html', 'path': os.path.basename(html_path),
                    'sha256': self.compute_hash(html_content), 'size_bytes': len(html_content.encode())
                })
                
                evidence['page_title'] = await page.title()
                evidence['final_url'] = page.url
                evidence['status'] = 'success'
            except Exception as e:
                evidence['status'] = 'error'
                evidence['error'] = str(e)
            finally:
                await browser.close()
        
        manifest_path = os.path.join(self.output_dir, f'manifest_{self.timestamp}.json')
        with open(manifest_path, 'w') as f:
            json.dump(evidence, f, indent=2)
        evidence['manifest_path'] = manifest_path
        return evidence

async def main():
    collector = EvidenceCollector()
    safe_urls = ["https://example.com", "https://www.google.com"]
    for url in safe_urls:
        print(f"\n🔍 Capturing: {url}")
        evidence = await collector.capture(url)
        print(f"   Status: {evidence['status']}")
        if evidence['status'] == 'success':
            print(f"   Title: {evidence['page_title']}")
            for artifact in evidence['artifacts']:
                print(f"   • {artifact['type']}: {artifact['sha256'][:16]}...")
    
    print("\n✅ Evidence collection complete. Keeping container alive...")
    # Keep the container running so Railway doesn't immediately delete it
    await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(main())