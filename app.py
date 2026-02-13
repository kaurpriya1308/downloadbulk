import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import os
import re
import json
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
import zipfile

# ─────────────────────────────────────────────
# Page Config
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Smart PDF Downloader",
    page_icon="📥",
    layout="wide"
)

# ─────────────────────────────────────────────
# Session State
# ─────────────────────────────────────────────
for key, default in {
    'found_pdfs': [],
    'downloaded_pdfs': {},
    'txt_output': "",
    'scan_done': False,
    'api_endpoints_found': [],
    'json_data_found': [],
    'scan_log': [],
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


# ─────────────────────────────────────────────
# HTTP Session with Browser-Like Headers
# ─────────────────────────────────────────────
def get_session():
    """Mimic a real Chrome browser"""
    s = requests.Session()
    s.headers.update({
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/121.0.0.0 Safari/537.36'
        ),
        'Accept': (
            'text/html,application/xhtml+xml,application/xml;'
            'q=0.9,image/webp,*/*;q=0.8'
        ),
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
    })
    return s


def get_api_session(referer_url):
    """Session configured for API/XHR calls"""
    s = requests.Session()
    s.headers.update({
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/121.0.0.0 Safari/537.36'
        ),
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': referer_url,
        'X-Requested-With': 'XMLHttpRequest',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
    })
    return s


# ─────────────────────────────────────────────
# PDF Extraction from JSON (recursive)
# ─────────────────────────────────────────────
def extract_pdfs_from_json(data, base_url):
    """
    Recursively search ANY JSON structure for PDF URLs.
    Handles nested dicts, lists, and string values.
    """
    pdf_links = set()

    def search(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str):
                    check_value(value, key)
                else:
                    search(value)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, str):
                    check_value(item)
                else:
                    search(item)
        elif isinstance(obj, str):
            check_value(obj)

    def check_value(value, key=""):
        value = value.strip()
        if not value:
            return

        # Direct PDF check
        if '.pdf' in value.lower():
            if value.startswith('http'):
                pdf_links.add(value)
            elif value.startswith('//'):
                pdf_links.add('https:' + value)
            elif value.startswith('/'):
                pdf_links.add(urljoin(base_url, value))
            elif value.startswith('www.'):
                pdf_links.add('https://' + value)
            else:
                pdf_links.add(urljoin(base_url, '/' + value))
            return

        # Check if key name suggests a file URL
        key_lower = key.lower()
        file_keys = [
            'url', 'file', 'path', 'link', 'href', 'src',
            'download', 'document', 'attachment', 'filepath',
            'file_url', 'download_url', 'pdf_url', 'doc_url',
            'report_url', 'media', 'asset', 'resource',
            'pdflink', 'pdf_link', 'filelink', 'file_link',
            'pdfurl', 'pdfpath', 'documenturl', 'documentpath',
            'image', 'img'  # sometimes PDFs stored as images
        ]

        if any(fk in key_lower for fk in file_keys):
            if value.startswith('http'):
                pdf_links.add(value)
            elif value.startswith('/'):
                pdf_links.add(urljoin(base_url, value))

    search(data)
    return pdf_links


# ─────────────────────────────────────────────
# Method 1: HTML Source Scan
# ─────────────────────────────────────────────
def scan_html_for_pdfs(url, session, log):
    """Extract PDF links from HTML page source"""
    pdf_links = set()

    try:
        log.append(f"📄 Fetching HTML: {url}")
        response = session.get(url, timeout=30, allow_redirects=True)
        response.raise_for_status()
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        # All anchor tags
        for tag in soup.find_all('a', href=True):
            href = tag['href'].strip()
            if not href or href.startswith('#') or href.startswith('javascript'):
                continue
            abs_url = urljoin(url, href)
            if '.pdf' in abs_url.lower():
                pdf_links.add(abs_url)

        # Embeds, iframes, objects
        for tag in soup.find_all(['embed', 'iframe', 'object']):
            src = tag.get('src', '') or tag.get('data', '')
            if src and '.pdf' in src.lower():
                pdf_links.add(urljoin(url, src))

        # Raw regex on full HTML
        raw_matches = re.findall(
            r'(?:href|src|data|url|content)=["\']([^"\']*\.pdf[^"\']*)["\']',
            html, re.IGNORECASE
        )
        for match in raw_matches:
            pdf_links.add(urljoin(url, match))

        log.append(f"   Found {len(pdf_links)} PDF links in HTML")

        return pdf_links, html

    except Exception as e:
        log.append(f"   ❌ HTML fetch error: {e}")
        return pdf_links, ""


# ─────────────────────────────────────────────
# Method 2: Find API Endpoints in JavaScript
# ─────────────────────────────────────────────
def find_api_endpoints_in_source(html, url, log):
    """
    Analyze page JavaScript to find API endpoints.
    Sites like Shriram Finance make fetch/axios calls
    to internal APIs — we find those URLs in the JS code.
    """
    endpoints = set()
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    # ── Pattern 1: Direct API URL strings ──
    api_patterns = [
        # fetch/axios calls
        r'(?:fetch|axios\.get|axios\.post|\.get|\.post)\s*\(\s*["\']([^"\']+)["\']',
        # API URL strings
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/wp-json/[^"\']+)["\']',
        r'["\'](/rest/[^"\']+)["\']',
        r'["\'](/v[0-9]+/[^"\']+)["\']',
        # URLs with common API indicators
        r'["\'](https?://[^"\']*(?:api|json|data|feed|service|endpoint)[^"\']*)["\']',
        # WordPress REST API
        r'["\'](/wp-admin/admin-ajax\.php[^"\']*)["\']',
        # Common CMS patterns
        r'["\']([^"\']*\.json)["\']',
        # ASP.NET / .NET API
        r'["\'](/[^"\']*(?:handler|ashx|asmx|svc)[^"\']*)["\']',
        # PHP endpoints
        r'["\']([^"\']*\.php\?[^"\']*)["\']',
    ]

    for pattern in api_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in matches:
            if match.startswith('http'):
                endpoints.add(match)
            elif match.startswith('/'):
                endpoints.add(base_url + match)

    # ── Pattern 2: Look for Next.js / React data endpoints ──
    nextjs_patterns = [
        r'["\'](/_next/data/[^"\']+)["\']',
        r'["\'](__NEXT_DATA__[^"\']*)["\']',
    ]
    for pattern in nextjs_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in matches:
            endpoints.add(urljoin(url, match))

    # ── Pattern 3: Find embedded JSON data ──
    # Some sites embed data directly in <script> tags
    soup = BeautifulSoup(html, 'html.parser')
    for script in soup.find_all('script'):
        script_text = script.string or ''

        # Look for JSON objects containing PDF references
        json_patterns = [
            r'(?:var|let|const)\s+\w+\s*=\s*(\{[^;]{100,}\.pdf[^;]*\})\s*;',
            r'(?:var|let|const)\s+\w+\s*=\s*(\[[^;]{100,}\.pdf[^;]*\])\s*;',
            r'window\.\w+\s*=\s*(\{[^;]{100,}\})\s*;',
            r'__NEXT_DATA__\s*=\s*(\{.+?\})\s*(?:</script>|;)',
        ]

        for pattern in json_patterns:
            matches = re.findall(pattern, script_text, re.DOTALL)
            for match in matches:
                try:
                    # Try to parse as JSON
                    data = json.loads(match)
                    pdfs = extract_pdfs_from_json(
                        data, base_url
                    )
                    if pdfs:
                        log.append(
                            f"   📦 Found {len(pdfs)} PDFs "
                            f"in embedded JSON data"
                        )
                        return endpoints, pdfs
                except json.JSONDecodeError:
                    pass

    # ── Pattern 4: Look for data attributes ──
    for tag in soup.find_all(attrs={"data-url": True}):
        data_url = tag['data-url']
        if '.pdf' in data_url.lower() or 'api' in data_url.lower():
            endpoints.add(urljoin(url, data_url))

    for tag in soup.find_all(attrs={"data-src": True}):
        data_src = tag['data-src']
        if '.pdf' in data_src.lower():
            endpoints.add(urljoin(url, data_src))

    log.append(f"   🔌 Found {len(endpoints)} potential API endpoints")
    return endpoints, set()


# ─────────────────────────────────────────────
# Method 3: Call Discovered API Endpoints
# ─────────────────────────────────────────────
def fetch_api_endpoints(endpoints, page_url, session, log):
    """
    Call each discovered API endpoint and parse
    the response for PDF links.
    """
    pdf_links = set()
    json_data_found = []
    base_url = f"{urlparse(page_url).scheme}://{urlparse(page_url).netloc}"

    api_session = get_api_session(page_url)

    # Also copy cookies from the main session
    api_session.cookies.update(session.cookies)

    for endpoint in endpoints:
        try:
            log.append(f"   🔌 Calling API: {endpoint[:100]}")
            resp = api_session.get(endpoint, timeout=15)

            if resp.status_code != 200:
                log.append(f"      ⚠️ Status {resp.status_code}")
                continue

            content_type = resp.headers.get('Content-Type', '')

            # Try JSON parse
            if 'json' in content_type or resp.text.strip().startswith(('{', '[')):
                try:
                    data = resp.json()
                    json_data_found.append({
                        'url': endpoint,
                        'preview': json.dumps(data, indent=2)[:500]
                    })

                    found = extract_pdfs_from_json(data, base_url)
                    pdf_links.update(found)
                    log.append(
                        f"      ✅ JSON parsed, found {len(found)} PDFs"
                    )
                except json.JSONDecodeError:
                    pass

            # Regex fallback on raw text
            raw_pdfs = re.findall(
                r'https?://[^\s"\'<>\\]+\.pdf(?:\?[^\s"\'<>\\]*)?',
                resp.text, re.IGNORECASE
            )
            for p in raw_pdfs:
                pdf_links.add(p)

            relative_pdfs = re.findall(
                r'["\'](/[^\s"\'<>\\]+\.pdf(?:\?[^\s"\'<>\\]*)?)["\']',
                resp.text, re.IGNORECASE
            )
            for p in relative_pdfs:
                pdf_links.add(urljoin(base_url, p))

        except requests.exceptions.Timeout:
            log.append(f"      ⏱️ Timeout")
        except Exception as e:
            log.append(f"      ❌ Error: {str(e)[:80]}")

    return pdf_links, json_data_found


# ─────────────────────────────────────────────
# Method 4: Try Common API Patterns
# ─────────────────────────────────────────────
def try_common_api_patterns(url, session, log):
    """
    Many websites use predictable API URL patterns.
    We try common ones based on the page URL.
    """
    pdf_links = set()
    json_data_found = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = [p for p in parsed.path.strip('/').split('/') if p]

    api_session = get_api_session(url)
    api_session.cookies.update(session.cookies)

    # ── Generate candidate API URLs ──
    candidates = []

    # WordPress patterns
    candidates.extend([
        f"{base_url}/wp-json/wp/v2/media?per_page=100&mime_type=application/pdf",
        f"{base_url}/wp-json/wp/v2/posts?per_page=100",
        f"{base_url}/wp-json/wp/v2/pages?per_page=100",
    ])

    # Common API path patterns
    if path_parts:
        last_part = path_parts[-1]
        candidates.extend([
            f"{base_url}/api/{'/'.join(path_parts)}",
            f"{base_url}/api/v1/{'/'.join(path_parts)}",
            f"{base_url}/api/v2/{'/'.join(path_parts)}",
            f"{base_url}/api/{last_part}",
            f"{base_url}/rest/{'/'.join(path_parts)}",
            f"{base_url}/data/{'/'.join(path_parts)}",
            f"{base_url}/json/{'/'.join(path_parts)}",
        ])

    # Shriram-like patterns (CMS with investor documents)
    investor_keywords = [
        'investor', 'annual', 'quarterly', 'financial',
        'report', 'document', 'download', 'disclosure',
        'governance', 'policy', 'result', 'presentation'
    ]

    for kw in investor_keywords:
        candidates.extend([
            f"{base_url}/api/{kw}",
            f"{base_url}/api/{kw}s",
            f"{base_url}/api/get-{kw}s",
            f"{base_url}/api/v1/{kw}",
            f"{base_url}/api/investor/{kw}",
            f"{base_url}/api/investors/{kw}",
            f"{base_url}/umbraco/api/{kw}/get",
            f"{base_url}/umbraco/surface/{kw}/get",
        ])

    # .json extension pattern
    candidates.append(url.rstrip('/') + '.json')
    for part in path_parts:
        candidates.append(f"{base_url}/{part}.json")

    # Deduplicate
    candidates = list(set(candidates))
    log.append(f"   🎯 Trying {len(candidates)} common API patterns...")

    found_count = 0
    for api_url in candidates:
        try:
            resp = api_session.get(api_url, timeout=8)
            if resp.status_code != 200:
                continue
            if len(resp.text) < 10:
                continue

            content_type = resp.headers.get('Content-Type', '')
            text = resp.text.strip()

            is_json = (
                'json' in content_type
                or text.startswith('{')
                or text.startswith('[')
            )

            if is_json:
                try:
                    data = resp.json()
                    found = extract_pdfs_from_json(data, base_url)
                    if found:
                        pdf_links.update(found)
                        found_count += len(found)
                        json_data_found.append({
                            'url': api_url,
                            'preview': json.dumps(data, indent=2)[:500]
                        })
                        log.append(
                            f"   ✅ HIT: {api_url} → {len(found)} PDFs"
                        )
                except json.JSONDecodeError:
                    pass

            # Also check raw text for PDF URLs
            raw = re.findall(
                r'https?://[^\s"\'<>\\]+\.pdf',
                resp.text, re.IGNORECASE
            )
            for p in raw:
                pdf_links.add(p)
                found_count += 1

        except (requests.exceptions.Timeout,
                requests.exceptions.ConnectionError):
            continue
        except Exception:
            continue

    log.append(
        f"   📊 Common patterns found {found_count} PDF links total"
    )
    return pdf_links, json_data_found


# ─────────────────────────────────────────────
# Method 5: Sitemap and robots.txt scan
# ─────────────────────────────────────────────
def scan_sitemap(url, session, log):
    """Check sitemap.xml for PDF links"""
    pdf_links = set()
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    sitemap_urls = [
        f"{base_url}/sitemap.xml",
        f"{base_url}/sitemap_index.xml",
        f"{base_url}/sitemap-documents.xml",
        f"{base_url}/post-sitemap.xml",
    ]

    for sitemap_url in sitemap_urls:
        try:
            resp = session.get(sitemap_url, timeout=10)
            if resp.status_code == 200 and 'xml' in resp.headers.get(
                'Content-Type', ''
            ):
                # Find PDF URLs in sitemap
                matches = re.findall(
                    r'<loc>([^<]*\.pdf[^<]*)</loc>',
                    resp.text, re.IGNORECASE
                )
                pdf_links.update(matches)

                if matches:
                    log.append(
                        f"   📍 Sitemap {sitemap_url}: "
                        f"{len(matches)} PDFs"
                    )
        except Exception:
            continue

    return pdf_links


# ─────────────────────────────────────────────
# Download Functions
# ─────────────────────────────────────────────
def download_single_pdf(pdf_url, session, index):
    """Download one PDF, return (filename, bytes, success, error)"""
    try:
        resp = session.get(
            pdf_url, timeout=60,
            stream=True, allow_redirects=True
        )
        resp.raise_for_status()

        # Determine filename
        filename = None

        # From Content-Disposition
        cd = resp.headers.get('Content-Disposition', '')
        if 'filename' in cd:
            match = re.findall(
                r'filename[^;=\n]*=["\']?([^"\';\n]+)', cd
            )
            if match:
                filename = match[0].strip()

        # From URL path
        if not filename:
            path = urlparse(pdf_url).path
            filename = os.path.basename(path)

        # Fallback
        if not filename or len(filename) < 3:
            filename = f"document_{index:03d}.pdf"

        if not filename.lower().endswith('.pdf'):
            filename += '.pdf'

        # Clean
        filename = re.sub(r'[<>:"/\\|?*%]', '_', filename)
        filename = re.sub(r'_{2,}', '_', filename)
        filename = filename.strip('_. ')

        content = resp.content

        # Verify PDF
        ct = resp.headers.get('Content-Type', '').lower()
        is_pdf = content[:5] == b'%PDF-' or 'pdf' in ct

        if not is_pdf and len(content) < 500:
            return (filename, None, False, "Not a valid PDF file")

        return (filename, content, True, None)

    except Exception as e:
        return (f"document_{index:03d}.pdf", None, False, str(e))


def download_all_pdfs(pdf_urls, max_workers=5, progress_bar=None):
    """Parallel download all PDFs"""
    downloaded = {}
    errors = []
    total = len(pdf_urls)
    if total == 0:
        return downloaded, errors

    session = get_session()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                download_single_pdf, url, session, idx
            ): (url, idx)
            for idx, url in enumerate(pdf_urls, 1)
        }

        done = 0
        for future in as_completed(futures):
            url, idx = futures[future]
            fname, content, ok, err = future.result()
            done += 1

            if progress_bar:
                progress_bar.progress(
                    done / total,
                    text=f"Downloading {done}/{total}: {fname}"
                )

            if ok and content:
                orig = fname
                c = 1
                while fname in downloaded:
                    name, ext = os.path.splitext(orig)
                    fname = f"{name}_{c}{ext}"
                    c += 1
                downloaded[fname] = content
            else:
                errors.append({
                    'url': url,
                    'filename': fname,
                    'error': err
                })

    return downloaded, errors


def create_zip(files_dict):
    """ZIP in memory"""
    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name, data in files_dict.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def generate_report(page_url, pdfs, downloaded, errors,
                    api_endpoints=None, json_data=None, scan_log=None):
    """Full TXT report"""
    lines = []
    lines.append("=" * 70)
    lines.append("SMART PDF DOWNLOAD REPORT")
    lines.append("=" * 70)
    lines.append(f"Source     : {page_url}")
    lines.append(f"Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Found      : {len(pdfs)}")
    lines.append(f"Downloaded : {len(downloaded)}")
    lines.append(f"Failed     : {len(errors)}")
    lines.append("=" * 70)
    lines.append("")

    lines.append("── ALL PDF LINKS FOUND ──")
    for i, link in enumerate(sorted(pdfs), 1):
        lines.append(f"  {i:3d}. {link}")
    lines.append("")

    if downloaded:
        lines.append("── DOWNLOADED FILES ──")
        for fname in sorted(downloaded.keys()):
            kb = len(downloaded[fname]) / 1024
            lines.append(f"  ✓ {fname} ({kb:.1f} KB)")
        lines.append("")

    if errors:
        lines.append("── FAILED ──")
        for e in errors:
            lines.append(f"  ✗ {e['url']}")
            lines.append(f"    {e['error']}")
        lines.append("")

    if api_endpoints:
        lines.append("── API ENDPOINTS DISCOVERED ──")
        for ep in api_endpoints:
            lines.append(f"  → {ep}")
        lines.append("")

    if json_data:
        lines.append("── JSON API RESPONSES ──")
        for jd in json_data:
            lines.append(f"  URL: {jd['url']}")
            lines.append(f"  Preview: {jd['preview'][:300]}")
            lines.append("")

    if scan_log:
        lines.append("── SCAN LOG ──")
        for entry in scan_log:
            lines.append(f"  {entry}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


# ─────────────────────────────────────────────
#  MASTER SCAN FUNCTION
# ─────────────────────────────────────────────
def smart_scan(url, try_apis=True, try_patterns=True, try_sitemap=True):
    """
    Run ALL methods to find every possible PDF.
    Returns: (pdf_set, api_endpoints, json_data, log)
    """
    all_pdfs = set()
    all_apis = set()
    all_json = []
    log = []

    session = get_session()

    # ── Step 1: HTML scan ──
    log.append("━━ STEP 1: HTML Source Scan ━━")
    html_pdfs, html_source = scan_html_for_pdfs(url, session, log)
    all_pdfs.update(html_pdfs)
    log.append(f"   Result: {len(html_pdfs)} PDFs from HTML")
    log.append("")

    if html_source and try_apis:
        # ── Step 2: Find API endpoints in JavaScript ──
        log.append("━━ STEP 2: JavaScript Analysis ━━")
        endpoints, embedded_pdfs = find_api_endpoints_in_source(
            html_source, url, log
        )
        all_pdfs.update(embedded_pdfs)
        all_apis.update(endpoints)
        log.append("")

        # ── Step 3: Call discovered API endpoints ──
        if endpoints:
            log.append("━━ STEP 3: Calling Discovered APIs ━━")
            api_pdfs, json_data = fetch_api_endpoints(
                endpoints, url, session, log
            )
            all_pdfs.update(api_pdfs)
            all_json.extend(json_data)
            log.append(f"   Result: {len(api_pdfs)} PDFs from APIs")
            log.append("")

    if try_patterns:
        # ── Step 4: Try common API patterns ──
        log.append("━━ STEP 4: Common API Pattern Matching ━━")
        pattern_pdfs, pattern_json = try_common_api_patterns(
            url, session, log
        )
        all_pdfs.update(pattern_pdfs)
        all_json.extend(pattern_json)
        log.append("")

    if try_sitemap:
        # ── Step 5: Sitemap scan ──
        log.append("━━ STEP 5: Sitemap Scan ━━")
        sitemap_pdfs = scan_sitemap(url, session, log)
        all_pdfs.update(sitemap_pdfs)
        log.append(f"   Result: {len(sitemap_pdfs)} PDFs from sitemap")
        log.append("")

    log.append(f"━━ TOTAL: {len(all_pdfs)} unique PDFs found ━━")

    return all_pdfs, list(all_apis), all_json, log


# ═════════════════════════════════════════════
#  STREAMLIT UI
# ═════════════════════════════════════════════

st.title("📥 Smart PDF Downloader")
st.markdown(
    "Finds PDFs hidden behind JavaScript & API calls — "
    "**no browser/Selenium needed**"
)

tab1, tab2, tab3 = st.tabs([
    "🔍 Smart Scan",
    "🔌 Manual API Call",
    "📋 Paste PDF URLs"
])

# ════════════════════════════════════════════
# TAB 1: SMART SCAN
# ════════════════════════════════════════════
with tab1:
    st.header("🔍 Smart Scan — Find All PDFs Automatically")
    st.markdown("""
    **How it works (no Selenium/Playwright needed):**
    1. Fetches page HTML and finds direct PDF links
    2. Analyzes JavaScript code to discover API endpoints
    3. Calls those APIs and parses JSON for hidden PDF URLs
    4. Tries 50+ common API patterns used by CMS platforms
    5. Checks sitemap.xml for PDF entries
    """)

    page_url = st.text_input(
        "🌐 Webpage URL",
        placeholder=(
            "https://www.shriramfinance.in/"
            "investors/investor-information"
        ),
        key="smart_url"
    )

    col1, col2 = st.columns(2)
    with col1:
        max_workers = st.slider(
            "Parallel downloads", 1, 10, 5,
            key="smart_workers"
        )
    with col2:
        scan_options = st.multiselect(
            "Scan methods",
            [
                "HTML Source",
                "JavaScript API Discovery",
                "Common API Patterns",
                "Sitemap"
            ],
            default=[
                "HTML Source",
                "JavaScript API Discovery",
                "Common API Patterns",
                "Sitemap"
            ]
        )

    # ── SCAN ──
    if st.button(
        "🚀 Scan for All PDFs", key="smart_scan_btn", type="primary"
    ):
        if not page_url.strip():
            st.error("Please enter a URL!")
        else:
            with st.spinner("🔍 Scanning... (this may take 30-60 seconds)"):
                pdfs, apis, json_data, log = smart_scan(
                    page_url.strip(),
                    try_apis="JavaScript API Discovery" in scan_options,
                    try_patterns="Common API Patterns" in scan_options,
                    try_sitemap="Sitemap" in scan_options,
                )

            st.session_state.found_pdfs = sorted(list(pdfs))
            st.session_state.api_endpoints_found = apis
            st.session_state.json_data_found = json_data
            st.session_state.scan_log = log
            st.session_state.scan_done = True

            if pdfs:
                st.success(f"✅ Found **{len(pdfs)}** unique PDFs!")
            else:
                st.warning(
                    "No PDFs found automatically. Try:\n"
                    "- Tab 2: Manual API Call (copy from Network tab)\n"
                    "- Tab 3: Paste PDF URLs directly"
                )

    # ── RESULTS ──
    if st.session_state.scan_done and st.session_state.found_pdfs:
        st.markdown("---")

        # Show scan log
        with st.expander(
            f"📋 Scan Log ({len(st.session_state.scan_log)} entries)"
        ):
            for entry in st.session_state.scan_log:
                st.text(entry)

        # Show JSON APIs found
        if st.session_state.json_data_found:
            with st.expander(
                f"📡 JSON APIs with PDFs "
                f"({len(st.session_state.json_data_found)} found)"
            ):
                for jd in st.session_state.json_data_found:
                    st.text(f"→ {jd['url']}")
                    st.code(jd['preview'][:400], language="json")

        # PDF list
        st.header(f"📄 Found {len(st.session_state.found_pdfs)} PDFs")

        with st.expander("View all PDF links", expanded=True):
            for i, link in enumerate(st.session_state.found_pdfs, 1):
                fname = os.path.basename(
                    urlparse(link).path
                ) or "unknown.pdf"
                st.text(f"{i:3d}. {fname}")
                st.caption(f"     {link}")

        # TXT download of links
        txt_links = "\n".join(st.session_state.found_pdfs)
        st.download_button(
            "📝 Download PDF Links (.TXT)",
            data=txt_links,
            file_name=(
                f"pdf_links_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            ),
            mime="text/plain"
        )

        # ── BULK DOWNLOAD ──
        if st.button(
            f"⬇️ Download All {len(st.session_state.found_pdfs)} PDFs",
            key="smart_dl", type="primary"
        ):
            progress = st.progress(0, text="Starting...")

            downloaded, errors = download_all_pdfs(
                st.session_state.found_pdfs,
                max_workers=max_workers,
                progress_bar=progress
            )
            progress.progress(1.0, text="Complete!")

            st.session_state.downloaded_pdfs = downloaded

            report = generate_report(
                page_url,
                st.session_state.found_pdfs,
                downloaded, errors,
                st.session_state.api_endpoints_found,
                st.session_state.json_data_found,
                st.session_state.scan_log
            )
            st.session_state.txt_output = report

            c1, c2 = st.columns(2)
            with c1:
                st.metric("✅ Downloaded", len(downloaded))
            with c2:
                st.metric("❌ Failed", len(errors))

            if errors:
                with st.expander("Show errors"):
                    for e in errors:
                        st.text(f"✗ {e['url']}: {e['error']}")

            st.markdown("---")
            st.header("📦 Get Your Files")

            d1, d2 = st.columns(2)
            with d1:
                if downloaded:
                    zdata = create_zip(downloaded)
                    st.download_button(
                        f"📦 Download ZIP ({len(downloaded)} PDFs)",
                        data=zdata,
                        file_name=(
                            f"pdfs_"
                            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                            f".zip"
                        ),
                        mime="application/zip",
                        type="primary"
                    )
            with d2:
                st.download_button(
                    "📝 Full Report (.TXT)",
                    data=report,
                    file_name=(
                        f"report_"
                        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    ),
                    mime="text/plain"
                )

            # Individual files
            with st.expander("Download individual PDFs"):
                for fname, content in downloaded.items():
                    kb = len(content) / 1024
                    st.download_button(
                        f"⬇️ {fname} ({kb:.1f} KB)",
                        data=content,
                        file_name=fname,
                        mime="application/pdf",
                        key=f"indiv_{fname}"
                    )


# ════════════════════════════════════════════
# TAB 2: MANUAL API CALL
# ════════════════════════════════════════════
with tab2:
    st.header("🔌 Manual API Call")
    st.markdown("""
    **If Smart Scan missed PDFs:**
    1. Open the website in Chrome
    2. Press **F12** → **Network** tab
    3. Click on tabs/buttons on the page
    4. Look for **XHR/Fetch** requests
    5. Right-click the request → **Copy → Copy URL**
    6. Paste it below
    """)

    api_url = st.text_input(
        "API URL (from Network tab)",
        placeholder="https://www.example.com/api/documents?category=reports"
    )

    api_headers = st.text_area(
        "Request Headers (optional — paste from Network tab)",
        height=120,
        placeholder=(
            '{\n'
            '  "Authorization": "Bearer xxx",\n'
            '  "Cookie": "session=abc"\n'
            '}'
        )
    )

    if st.button("🔌 Fetch & Extract PDFs", key="manual_api"):
        if not api_url.strip():
            st.error("Enter an API URL!")
        else:
            with st.spinner("Fetching API..."):
                session = get_api_session(api_url)

                # Parse custom headers
                if api_headers.strip():
                    try:
                        custom = json.loads(api_headers)
                        session.headers.update(custom)
                    except json.JSONDecodeError:
                        for line in api_headers.strip().split('\n'):
                            if ':' in line:
                                k, v = line.split(':', 1)
                                session.headers[k.strip()] = v.strip()

                try:
                    resp = session.get(api_url.strip(), timeout=30)
                    resp.raise_for_status()

                    st.success(f"✅ Status {resp.status_code}")

                    # Try JSON
                    try:
                        data = resp.json()
                        st.json(data)

                        base = (
                            f"{urlparse(api_url).scheme}://"
                            f"{urlparse(api_url).netloc}"
                        )
                        pdfs = extract_pdfs_from_json(data, base)

                        if pdfs:
                            st.success(f"Found {len(pdfs)} PDFs!")
                            pdf_list = sorted(list(pdfs))

                            for i, p in enumerate(pdf_list, 1):
                                st.text(f"{i}. {p}")

                            st.session_state.found_pdfs = pdf_list
                            st.session_state.scan_done = True

                            txt = "\n".join(pdf_list)
                            st.download_button(
                                "📝 Save as .TXT",
                                data=txt,
                                file_name="api_pdfs.txt",
                                mime="text/plain"
                            )
                        else:
                            st.warning("No PDF links in this response")

                    except json.JSONDecodeError:
                        st.code(resp.text[:2000])

                        pdfs = re.findall(
                            r'https?://[^\s"\'<>]+\.pdf',
                            resp.text, re.IGNORECASE
                        )
                        if pdfs:
                            st.success(f"Found {len(pdfs)} PDF URLs")
                            for p in pdfs:
                                st.text(p)

                except Exception as e:
                    st.error(f"Error: {e}")


# ════════════════════════════════════════════
# TAB 3: PASTE URLS DIRECTLY
# ════════════════════════════════════════════
with tab3:
    st.header("📋 Paste PDF URLs")

    direct_urls = st.text_area(
        "PDF URLs (one per line)",
        height=250,
        placeholder=(
            "https://example.com/report1.pdf\n"
            "https://example.com/report2.pdf"
        )
    )

    direct_workers = st.slider(
        "Parallel downloads", 1, 10, 5, key="direct_w"
    )

    if st.button("⬇️ Download All", key="direct_dl", type="primary"):
        urls = [
            u.strip() for u in direct_urls.strip().split('\n')
            if u.strip()
        ]
        if not urls:
            st.error("Paste at least one URL!")
        else:
            progress = st.progress(0)
            downloaded, errors = download_all_pdfs(
                urls, max_workers=direct_workers,
                progress_bar=progress
            )
            progress.progress(1.0, text="Done!")

            report = generate_report(
                "Direct input", urls, downloaded, errors
            )

            st.success(f"Downloaded {len(downloaded)} of {len(urls)}")

            if errors:
                with st.expander("Errors"):
                    for e in errors:
                        st.text(f"✗ {e['url']}: {e['error']}")

            d1, d2 = st.columns(2)
            with d1:
                if downloaded:
                    zdata = create_zip(downloaded)
                    st.download_button(
                        f"📦 ZIP ({len(downloaded)} files)",
                        data=zdata,
                        file_name="pdfs.zip",
                        mime="application/zip",
                        type="primary"
                    )
            with d2:
                st.download_button(
                    "📝 Report (.TXT)",
                    data=report,
                    file_name="report.txt",
                    mime="text/plain"
                )


# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.header("ℹ️ How It Works")
    st.markdown("""
    ### No Browser Needed!
    Unlike Selenium/Playwright, this app:

    1. **Reads page HTML** via HTTP request
    2. **Parses JavaScript** to find API URLs
    3. **Calls APIs directly** (like Network tab)
    4. **Tries 50+ common patterns** for CMS APIs
    5. **Checks sitemap.xml** for PDF entries

    All using pure Python — works everywhere.

    ---

    ### 🎯 For Sites Like Shriram Finance
    The app detects that PDFs are loaded via
    API calls and tries to find & call those
    APIs automatically.

    ### 💡 If Auto-Scan Misses PDFs
    1. Open the site in Chrome
    2. Press F12 → Network tab
    3. Click tabs on the page
    4. Find the XHR request with PDF data
    5. Copy URL → paste in Tab 2
    """)

    st.markdown("---")

    if st.button("🗑️ Clear All"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
