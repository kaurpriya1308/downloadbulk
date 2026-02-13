import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import os
import re
import json
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
defaults = {
    'all_links': [],          # every link found (unfiltered)
    'filtered_pdfs': [],      # after applying filters
    'downloaded_pdfs': {},
    'scan_done': False,
    'scan_log': [],
    'json_data_found': [],
    'api_endpoints_found': [],
}
for key, val in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val


# ─────────────────────────────────────────────
# HTTP Sessions
# ─────────────────────────────────────────────
def get_session():
    s = requests.Session()
    s.headers.update({
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/121.0.0.0 Safari/537.36'
        ),
        'Accept': (
            'text/html,application/xhtml+xml,'
            'application/xml;q=0.9,*/*;q=0.8'
        ),
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
    })
    return s


def get_api_session(referer):
    s = requests.Session()
    s.headers.update({
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/121.0.0.0 Safari/537.36'
        ),
        'Accept': 'application/json, text/plain, */*',
        'Referer': referer,
        'X-Requested-With': 'XMLHttpRequest',
    })
    return s


# ─────────────────────────────────────────────
# FILTER FUNCTION — The Core Fix
# ─────────────────────────────────────────────
def filter_pdf_links(all_links, must_contain_keywords, exclude_keywords):
    """
    Filter links to keep only actual PDF documents.

    Args:
        all_links: list of all discovered URLs
        must_contain_keywords: link MUST contain at least one
                               of these (e.g., ['.pdf'])
        exclude_keywords: link must NOT contain any of these
                          (e.g., ['.jpg', '.png', '.svg'])

    Returns:
        list of filtered PDF URLs
    """
    filtered = []

    # Default excludes — always skip these
    default_excludes = [
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp',
        '.ico', '.bmp', '.tiff',           # images
        '.css', '.woff', '.woff2', '.ttf',  # fonts/styles
        '.mp4', '.mp3', '.avi', '.mov',     # media
        'facebook.com', 'twitter.com', 'linkedin.com',
        'instagram.com', 'youtube.com',     # social media
        'play.google.com', 'apps.apple.com',  # app stores
        '#', 'javascript:', 'mailto:',      # non-URLs
    ]

    all_excludes = default_excludes + [
        kw.strip().lower()
        for kw in exclude_keywords
        if kw.strip()
    ]

    must_keywords = [
        kw.strip().lower()
        for kw in must_contain_keywords
        if kw.strip()
    ]

    for link in all_links:
        link_lower = link.lower().strip()

        if not link_lower or not link_lower.startswith('http'):
            continue

        # ── EXCLUDE CHECK ──
        skip = False
        for exc in all_excludes:
            if exc in link_lower:
                skip = True
                break
        if skip:
            continue

        # ── MUST CONTAIN CHECK ──
        # Link must contain at least ONE of the must-have keywords
        if must_keywords:
            has_keyword = False
            for kw in must_keywords:
                if kw in link_lower:
                    has_keyword = True
                    break
            if not has_keyword:
                continue

        filtered.append(link)

    # Deduplicate preserving order
    seen = set()
    unique = []
    for link in filtered:
        if link not in seen:
            seen.add(link)
            unique.append(link)

    return unique


# ─────────────────────────────────────────────
# Extract PDFs from JSON (recursive)
# ─────────────────────────────────────────────
def extract_urls_from_json(data, base_url):
    """
    Recursively extract ALL URLs from any JSON structure.
    Filtering happens later — this just finds URLs.
    """
    urls = set()

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

        # Check if it looks like a URL or path
        if value.startswith('http'):
            urls.add(value)
        elif value.startswith('//'):
            urls.add('https:' + value)
        elif value.startswith('/') and (
            '.' in value.split('/')[-1]
        ):
            # Relative path with file extension
            urls.add(urljoin(base_url, value))
        elif key.lower() in [
            'url', 'file', 'path', 'link', 'href', 'src',
            'download', 'document', 'attachment', 'filepath',
            'file_url', 'download_url', 'pdf_url', 'media',
            'asset', 'resource', 'pdflink', 'pdf_link',
        ]:
            if value.startswith('/'):
                urls.add(urljoin(base_url, value))
            elif value.startswith('http'):
                urls.add(value)

    search(data)
    return urls


# ─────────────────────────────────────────────
# Method 1: HTML Source Scan
# ─────────────────────────────────────────────
def scan_html(url, session, log):
    """Get all links from HTML — NO filtering here"""
    all_links = set()

    try:
        log.append(f"📄 Fetching: {url}")
        resp = session.get(url, timeout=30, allow_redirects=True)
        resp.raise_for_status()
        html = resp.text
        soup = BeautifulSoup(html, 'html.parser')

        # All <a> tags
        for tag in soup.find_all('a', href=True):
            href = tag['href'].strip()
            if href and not href.startswith(('#', 'javascript', 'mailto')):
                all_links.add(urljoin(url, href))

        # Embeds, iframes, objects
        for tag in soup.find_all(['embed', 'iframe', 'object']):
            src = tag.get('src', '') or tag.get('data', '')
            if src:
                all_links.add(urljoin(url, src))

        # Data attributes
        for tag in soup.find_all(attrs=True):
            for attr_name, attr_val in tag.attrs.items():
                if isinstance(attr_val, str) and (
                    attr_name.startswith('data-') and
                    ('url' in attr_name.lower() or
                     'src' in attr_name.lower() or
                     'href' in attr_name.lower())
                ):
                    if attr_val.startswith(('http', '/')):
                        all_links.add(urljoin(url, attr_val))

        log.append(f"   Found {len(all_links)} total links in HTML")
        return all_links, html

    except Exception as e:
        log.append(f"   ❌ Error: {e}")
        return all_links, ""


# ─────────────────────────────────────────────
# Method 2: Find & Call API Endpoints
# ─────────────────────────────────────────────
def find_apis_in_js(html, url, log):
    """Find API endpoint URLs in JavaScript code"""
    endpoints = set()
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    patterns = [
        r'(?:fetch|axios\.get|axios\.post|\.get|\.post)\s*\(\s*["\']([^"\']+)["\']',
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/wp-json/[^"\']+)["\']',
        r'["\'](/rest/[^"\']+)["\']',
        r'["\']([^"\']*\.json(?:\?[^"\']*)?)["\']',
        r'["\'](/v[0-9]+/[^"\']+)["\']',
        r'["\'](/umbraco/[^"\']+)["\']',
        r'(?:apiUrl|apiBase|baseUrl|endpoint)\s*[:=]\s*["\']([^"\']+)["\']',
    ]

    for pattern in patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in matches:
            if match.startswith('http'):
                endpoints.add(match)
            elif match.startswith('/'):
                endpoints.add(base_url + match)

    # Embedded JSON in script tags
    embedded_urls = set()
    soup = BeautifulSoup(html, 'html.parser')
    for script in soup.find_all('script'):
        text = script.string or ''
        # Find large JSON blocks
        json_matches = re.findall(
            r'(?:window\.\w+|var\s+\w+|let\s+\w+|const\s+\w+)\s*=\s*(\{.{200,}?\});',
            text, re.DOTALL
        )
        for jm in json_matches:
            try:
                data = json.loads(jm)
                found = extract_urls_from_json(data, base_url)
                embedded_urls.update(found)
            except json.JSONDecodeError:
                pass

        # Also try __NEXT_DATA__
        next_match = re.search(
            r'__NEXT_DATA__\s*=\s*(\{.+?\})\s*(?:</script>|;\s*__)',
            text, re.DOTALL
        )
        if next_match:
            try:
                data = json.loads(next_match.group(1))
                found = extract_urls_from_json(data, base_url)
                embedded_urls.update(found)
            except json.JSONDecodeError:
                pass

    log.append(f"   🔌 Found {len(endpoints)} API endpoints")
    log.append(f"   📦 Found {len(embedded_urls)} URLs in embedded JSON")

    return endpoints, embedded_urls


def call_apis(endpoints, page_url, session, log):
    """Call each API endpoint and collect all URLs from responses"""
    all_urls = set()
    json_data_list = []
    base_url = f"{urlparse(page_url).scheme}://{urlparse(page_url).netloc}"

    api_session = get_api_session(page_url)
    api_session.cookies.update(session.cookies)

    for ep in endpoints:
        try:
            resp = api_session.get(ep, timeout=10)
            if resp.status_code != 200:
                continue
            if len(resp.text) < 10:
                continue

            text = resp.text.strip()
            is_json = text.startswith(('{', '['))

            if is_json:
                try:
                    data = resp.json()
                    found = extract_urls_from_json(data, base_url)
                    all_urls.update(found)

                    if found:
                        json_data_list.append({
                            'url': ep,
                            'preview': json.dumps(data, indent=2)[:500]
                        })
                        log.append(
                            f"   ✅ {ep[:80]} → {len(found)} URLs"
                        )
                except json.JSONDecodeError:
                    pass

            # Regex fallback
            raw = re.findall(
                r'https?://[^\s"\'<>\\]+\.[a-zA-Z]{2,5}(?:\?[^\s"\'<>\\]*)?',
                resp.text
            )
            all_urls.update(raw)

        except Exception:
            continue

    return all_urls, json_data_list


# ─────────────────────────────────────────────
# Method 3: Common API Patterns
# ─────────────────────────────────────────────
def try_common_patterns(url, session, log):
    """Try common CMS API patterns"""
    all_urls = set()
    json_data_list = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = [p for p in parsed.path.strip('/').split('/') if p]

    api_session = get_api_session(url)
    api_session.cookies.update(session.cookies)

    candidates = set()

    # WordPress
    candidates.update([
        f"{base_url}/wp-json/wp/v2/media?per_page=100&mime_type=application/pdf",
        f"{base_url}/wp-json/wp/v2/posts?per_page=100",
        f"{base_url}/wp-json/wp/v2/pages?per_page=100",
    ])

    # Path-based patterns
    if path_parts:
        last = path_parts[-1]
        full = '/'.join(path_parts)
        for prefix in ['/api', '/api/v1', '/api/v2', '/rest', '/data', '/json']:
            candidates.add(f"{base_url}{prefix}/{full}")
            candidates.add(f"{base_url}{prefix}/{last}")

    # Investor-specific keywords
    keywords = [
        'investor', 'annual-report', 'quarterly-result',
        'financial-result', 'document', 'download',
        'disclosure', 'governance', 'policy',
        'shareholder', 'board-meeting', 'agm',
        'investor-information', 'investor-documents',
    ]
    for kw in keywords:
        candidates.add(f"{base_url}/api/{kw}")
        candidates.add(f"{base_url}/api/v1/{kw}")
        candidates.add(f"{base_url}/api/investor/{kw}")

    # .json extension
    candidates.add(url.rstrip('/') + '.json')

    log.append(f"   🎯 Trying {len(candidates)} API patterns...")

    for api_url in candidates:
        try:
            resp = api_session.get(api_url, timeout=8)
            if resp.status_code != 200 or len(resp.text) < 10:
                continue

            text = resp.text.strip()
            if text.startswith(('{', '[')):
                try:
                    data = resp.json()
                    found = extract_urls_from_json(data, base_url)
                    all_urls.update(found)
                    if found:
                        json_data_list.append({
                            'url': api_url,
                            'preview': json.dumps(data, indent=2)[:500]
                        })
                        log.append(
                            f"   ✅ HIT: {api_url[:80]} → {len(found)} URLs"
                        )
                except json.JSONDecodeError:
                    pass
        except Exception:
            continue

    return all_urls, json_data_list


# ─────────────────────────────────────────────
# Method 4: Sitemap
# ─────────────────────────────────────────────
def scan_sitemap(url, session, log):
    urls = set()
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    for sm in [f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"]:
        try:
            resp = session.get(sm, timeout=10)
            if resp.status_code == 200:
                matches = re.findall(r'<loc>([^<]+)</loc>', resp.text)
                urls.update(matches)
        except Exception:
            continue

    return urls


# ─────────────────────────────────────────────
# Download Functions
# ─────────────────────────────────────────────
def download_pdf(pdf_url, session, index):
    try:
        resp = session.get(pdf_url, timeout=60, allow_redirects=True)
        resp.raise_for_status()

        filename = None
        cd = resp.headers.get('Content-Disposition', '')
        if 'filename' in cd:
            match = re.findall(
                r'filename[^;=\n]*=["\']?([^"\';\n]+)', cd
            )
            if match:
                filename = match[0].strip()

        if not filename:
            filename = os.path.basename(urlparse(pdf_url).path)

        if not filename or len(filename) < 3:
            filename = f"document_{index:03d}.pdf"

        if not filename.lower().endswith('.pdf'):
            filename += '.pdf'

        filename = re.sub(r'[<>:"/\\|?*%]', '_', filename)
        filename = re.sub(r'_{2,}', '_', filename).strip('_. ')

        content = resp.content
        ct = resp.headers.get('Content-Type', '').lower()
        is_pdf = content[:5] == b'%PDF-' or 'pdf' in ct

        if not is_pdf and len(content) < 500:
            return (filename, None, False, "Not a valid PDF")

        return (filename, content, True, None)

    except Exception as e:
        return (f"document_{index:03d}.pdf", None, False, str(e))


def download_all(pdf_urls, max_workers=5, progress_bar=None):
    downloaded = {}
    errors = []
    total = len(pdf_urls)
    if not total:
        return downloaded, errors

    session = get_session()

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(download_pdf, url, session, i): (url, i)
            for i, url in enumerate(pdf_urls, 1)
        }
        done = 0
        for f in as_completed(futures):
            url, idx = futures[f]
            fname, content, ok, err = f.result()
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
                    n, e = os.path.splitext(orig)
                    fname = f"{n}_{c}{e}"
                    c += 1
                downloaded[fname] = content
            else:
                errors.append({'url': url, 'filename': fname, 'error': err})

    return downloaded, errors


def create_zip(files):
    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


def generate_report(page_url, pdfs, downloaded, errors,
                    apis=None, json_data=None, log=None):
    lines = [
        "=" * 70,
        "PDF DOWNLOAD REPORT",
        "=" * 70,
        f"Source     : {page_url}",
        f"Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Found      : {len(pdfs)}",
        f"Downloaded : {len(downloaded)}",
        f"Failed     : {len(errors)}",
        "=" * 70, "",
        "── PDF LINKS ──",
    ]
    for i, link in enumerate(sorted(pdfs), 1):
        lines.append(f"  {i:3d}. {link}")
    lines.append("")

    if downloaded:
        lines.append("── DOWNLOADED ──")
        for fn in sorted(downloaded):
            kb = len(downloaded[fn]) / 1024
            lines.append(f"  ✓ {fn} ({kb:.1f} KB)")
        lines.append("")

    if errors:
        lines.append("── FAILED ──")
        for e in errors:
            lines.append(f"  ✗ {e['url']}: {e['error']}")
        lines.append("")

    if json_data:
        lines.append("── JSON APIs ──")
        for jd in json_data:
            lines.append(f"  → {jd['url']}")
        lines.append("")

    if log:
        lines.append("── SCAN LOG ──")
        lines.extend(f"  {l}" for l in log)

    lines.append("=" * 70)
    return "\n".join(lines)


# ─────────────────────────────────────────────
# MASTER SCAN
# ─────────────────────────────────────────────
def smart_scan(url, methods):
    """Run selected scan methods, return ALL links (unfiltered)"""
    all_links = set()
    apis_found = []
    json_found = []
    log = []
    session = get_session()

    if "HTML Source" in methods:
        log.append("━━ STEP 1: HTML Source ━━")
        html_links, html_source = scan_html(url, session, log)
        all_links.update(html_links)
        log.append("")

        if "JavaScript API Discovery" in methods and html_source:
            log.append("━━ STEP 2: JavaScript Analysis ━━")
            endpoints, embedded = find_apis_in_js(html_source, url, log)
            all_links.update(embedded)
            apis_found.extend(endpoints)
            log.append("")

            if endpoints:
                log.append("━━ STEP 3: Calling APIs ━━")
                api_urls, jdata = call_apis(endpoints, url, session, log)
                all_links.update(api_urls)
                json_found.extend(jdata)
                log.append("")

    if "Common API Patterns" in methods:
        log.append("━━ STEP 4: Common Patterns ━━")
        pat_urls, pat_json = try_common_patterns(url, session, log)
        all_links.update(pat_urls)
        json_found.extend(pat_json)
        log.append("")

    if "Sitemap" in methods:
        log.append("━━ STEP 5: Sitemap ━━")
        sm_urls = scan_sitemap(url, session, log)
        all_links.update(sm_urls)
        log.append(f"   Sitemap: {len(sm_urls)} URLs")
        log.append("")

    log.append(f"━━ TOTAL RAW LINKS: {len(all_links)} ━━")
    return all_links, apis_found, json_found, log


# ═════════════════════════════════════════════
# STREAMLIT UI
# ═════════════════════════════════════════════

st.title("📥 Smart PDF Downloader")
st.markdown(
    "Finds PDFs from JavaScript APIs & JSON responses — "
    "**with smart filtering to get only real PDFs**"
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
    st.header("🔍 Smart Scan")

    page_url = st.text_input(
        "🌐 Webpage URL",
        placeholder="https://www.shriramfinance.in/investors/investor-information",
        key="smart_url"
    )

    # ── SETTINGS ──
    with st.expander("⚙️ Scan Settings", expanded=False):
        col_a, col_b = st.columns(2)
        with col_a:
            max_workers = st.slider("Parallel downloads", 1, 10, 5)
        with col_b:
            scan_methods = st.multiselect(
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

    # ── FILTER SETTINGS (ALWAYS VISIBLE) ──
    st.markdown("---")
    st.subheader("🔧 PDF Filter Settings")
    st.markdown(
        "Control which links are treated as PDF documents. "
        "Add keywords that PDF URLs on this site contain."
    )

    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:
        st.markdown("**✅ Must contain (at least one):**")
        st.caption(
            "Only links containing at least ONE of these "
            "keywords will be kept"
        )

        default_must = ".pdf"
        must_contain_input = st.text_area(
            "Include keywords (one per line)",
            value=default_must,
            height=120,
            help=(
                "Add keywords like:\n"
                ".pdf\n"
                "/download/\n"
                "/documents/\n"
                "getfile\n"
                "attachment"
            ),
            key="must_contain"
        )

    with filter_col2:
        st.markdown("**❌ Must NOT contain (auto-excluded):**")
        st.caption(
            "Links with these keywords are always removed. "
            "Add more if needed."
        )

        default_exclude = (
            ".jpg\n.jpeg\n.png\n.gif\n.svg\n.webp\n"
            ".ico\n.css\n.woff\n.woff2\n.ttf\n"
            ".mp4\n.mp3\n.avi\n"
            "facebook.com\ntwitter.com\nlinkedin.com\n"
            "instagram.com\nyoutube.com\n"
            "play.google.com\napps.apple.com"
        )
        exclude_input = st.text_area(
            "Exclude keywords (one per line)",
            value=default_exclude,
            height=120,
            help="Add more patterns to exclude",
            key="exclude_kw"
        )

    # Parse filter inputs
    must_keywords = [
        kw.strip()
        for kw in must_contain_input.strip().split('\n')
        if kw.strip()
    ]
    exclude_keywords = [
        kw.strip()
        for kw in exclude_input.strip().split('\n')
        if kw.strip()
    ]

    st.info(
        f"**Active filters:** Must contain: `{must_keywords}` | "
        f"Excluding: `{len(exclude_keywords)}` patterns"
    )

    # ── SCAN BUTTON ──
    st.markdown("---")

    if st.button(
        "🚀 Scan for PDFs", key="scan_btn", type="primary"
    ):
        if not page_url.strip():
            st.error("Please enter a URL!")
        else:
            with st.spinner(
                "🔍 Scanning page, JavaScript, APIs... "
                "(30-60 seconds)"
            ):
                all_links, apis, json_data, log = smart_scan(
                    page_url.strip(), scan_methods
                )

            # Store raw links
            st.session_state.all_links = sorted(list(all_links))
            st.session_state.api_endpoints_found = apis
            st.session_state.json_data_found = json_data
            st.session_state.scan_log = log

            # Apply filter
            filtered = filter_pdf_links(
                list(all_links), must_keywords, exclude_keywords
            )
            st.session_state.filtered_pdfs = filtered
            st.session_state.scan_done = True

            st.success(
                f"✅ Found **{len(all_links)}** total links → "
                f"**{len(filtered)}** PDFs after filtering"
            )

    # ── RESULTS ──
    if st.session_state.scan_done:

        # Show raw vs filtered count
        st.markdown("---")
        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric(
                "🔗 Total Links Found",
                len(st.session_state.all_links)
            )
        with m2:
            st.metric(
                "📄 PDFs After Filter",
                len(st.session_state.filtered_pdfs)
            )
        with m3:
            st.metric(
                "🚫 Filtered Out",
                len(st.session_state.all_links) -
                len(st.session_state.filtered_pdfs)
            )

        # ── RE-FILTER BUTTON ──
        # User can change keywords above and re-filter
        # without re-scanning
        if st.button(
            "🔄 Re-apply Filter (after changing keywords above)",
            key="refilter"
        ):
            filtered = filter_pdf_links(
                st.session_state.all_links,
                must_keywords,
                exclude_keywords
            )
            st.session_state.filtered_pdfs = filtered
            st.success(
                f"Filtered: {len(filtered)} PDFs "
                f"from {len(st.session_state.all_links)} total links"
            )
            st.rerun()

        # Scan log
        with st.expander(
            f"📋 Scan Log ({len(st.session_state.scan_log)} entries)"
        ):
            for entry in st.session_state.scan_log:
                st.text(entry)

        # JSON APIs
        if st.session_state.json_data_found:
            with st.expander(
                f"📡 JSON APIs ({len(st.session_state.json_data_found)})"
            ):
                for jd in st.session_state.json_data_found:
                    st.text(f"→ {jd['url']}")
                    st.code(jd['preview'][:400], language="json")

        # ── PDF LIST ──
        if st.session_state.filtered_pdfs:
            st.header(
                f"📄 {len(st.session_state.filtered_pdfs)} PDFs Ready"
            )

            with st.expander("View all filtered PDF links", expanded=True):
                for i, link in enumerate(
                    st.session_state.filtered_pdfs, 1
                ):
                    fname = os.path.basename(
                        urlparse(link).path
                    ) or "unknown.pdf"
                    st.text(f"{i:3d}. {fname}")
                    st.caption(f"     {link}")

            # TXT download
            txt = "\n".join(st.session_state.filtered_pdfs)
            st.download_button(
                "📝 Download PDF Links (.TXT)",
                data=txt,
                file_name=(
                    f"pdf_links_"
                    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                ),
                mime="text/plain"
            )

            # ── DOWNLOAD ALL ──
            if st.button(
                f"⬇️ Download All "
                f"{len(st.session_state.filtered_pdfs)} PDFs",
                key="dl_all", type="primary"
            ):
                prog = st.progress(0, text="Starting...")
                downloaded, errors = download_all(
                    st.session_state.filtered_pdfs,
                    max_workers=max_workers,
                    progress_bar=prog
                )
                prog.progress(1.0, text="Complete!")

                st.session_state.downloaded_pdfs = downloaded

                report = generate_report(
                    page_url,
                    st.session_state.filtered_pdfs,
                    downloaded, errors,
                    st.session_state.api_endpoints_found,
                    st.session_state.json_data_found,
                    st.session_state.scan_log
                )

                c1, c2 = st.columns(2)
                with c1:
                    st.metric("✅ Downloaded", len(downloaded))
                with c2:
                    st.metric("❌ Failed", len(errors))

                if errors:
                    with st.expander("Show errors"):
                        for e in errors:
                            st.text(
                                f"✗ {e['url']}: {e['error']}"
                            )

                st.markdown("---")
                st.header("📦 Get Your Files")

                d1, d2 = st.columns(2)
                with d1:
                    if downloaded:
                        zdata = create_zip(downloaded)
                        st.download_button(
                            f"📦 Download ZIP "
                            f"({len(downloaded)} PDFs)",
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
                            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                            f".txt"
                        ),
                        mime="text/plain"
                    )

                with st.expander("Download individual PDFs"):
                    for fn, content in downloaded.items():
                        kb = len(content) / 1024
                        st.download_button(
                            f"⬇️ {fn} ({kb:.1f} KB)",
                            data=content,
                            file_name=fn,
                            mime="application/pdf",
                            key=f"ind_{fn}"
                        )

        # ── SHOW ALL RAW LINKS (for debugging) ──
        with st.expander(
            f"🔧 All raw links (unfiltered): "
            f"{len(st.session_state.all_links)}"
        ):
            st.caption(
                "These are ALL links found before filtering. "
                "If PDFs are missing, check here and adjust "
                "filter keywords above."
            )
            for i, link in enumerate(
                st.session_state.all_links[:200], 1
            ):
                is_pdf = any(
                    kw in link.lower()
                    for kw in must_keywords
                )
                icon = "📄" if is_pdf else "🔗"
                st.text(f"{icon} {i:3d}. {link[:120]}")


# ════════════════════════════════════════════
# TAB 2: MANUAL API CALL
# ════════════════════════════════════════════
with tab2:
    st.header("🔌 Manual API Call")
    st.markdown("""
    **Steps:**
    1. Open website in Chrome
    2. Press **F12** → **Network** tab
    3. Click tabs/buttons on the page
    4. Find XHR requests with document data
    5. Right-click → **Copy → Copy URL**
    6. Paste below
    """)

    api_url = st.text_input(
        "API URL",
        placeholder="https://example.com/api/documents",
        key="api_url_input"
    )

    api_headers = st.text_area(
        "Headers (optional)",
        height=100,
        placeholder='{"Cookie": "session=abc123"}',
        key="api_headers_input"
    )

    if st.button("🔌 Fetch & Extract", key="fetch_api"):
        if not api_url.strip():
            st.error("Enter a URL!")
        else:
            with st.spinner("Fetching..."):
                session = get_api_session(api_url)
                if api_headers.strip():
                    try:
                        custom = json.loads(api_headers)
                        session.headers.update(custom)
                    except json.JSONDecodeError:
                        for line in api_headers.strip().split('\n'):
                            if ':' in line:
                                k, v = line.split(':', 1)
                                session.headers[
                                    k.strip()
                                ] = v.strip()

                try:
                    resp = session.get(api_url.strip(), timeout=30)
                    resp.raise_for_status()
                    st.success(f"Status: {resp.status_code}")

                    try:
                        data = resp.json()
                        st.json(data)

                        base = (
                            f"{urlparse(api_url).scheme}://"
                            f"{urlparse(api_url).netloc}"
                        )
                        all_urls = extract_urls_from_json(data, base)
                        pdfs = filter_pdf_links(
                            list(all_urls),
                            ['.pdf'],
                            []
                        )

                        if pdfs:
                            st.success(f"Found {len(pdfs)} PDFs!")
                            for i, p in enumerate(pdfs, 1):
                                st.text(f"{i}. {p}")

                            txt = "\n".join(pdfs)
                            st.download_button(
                                "📝 Save as .TXT",
                                data=txt,
                                file_name="api_pdfs.txt",
                                mime="text/plain"
                            )

                            st.session_state.filtered_pdfs = pdfs
                            st.session_state.scan_done = True
                        else:
                            st.warning("No PDF links found")
                            st.info(
                                f"All URLs in response: "
                                f"{len(all_urls)}"
                            )
                            for u in list(all_urls)[:20]:
                                st.text(u)

                    except json.JSONDecodeError:
                        st.code(resp.text[:3000])

                except Exception as e:
                    st.error(f"Error: {e}")


# ════════════════════════════════════════════
# TAB 3: PASTE URLS
# ════════════════════════════════════════════
with tab3:
    st.header("📋 Paste PDF URLs")

    direct_input = st.text_area(
        "PDF URLs (one per line)",
        height=250,
        placeholder=(
            "https://example.com/report1.pdf\n"
            "https://example.com/report2.pdf"
        )
    )

    dw = st.slider("Parallel downloads", 1, 10, 5, key="dw3")

    if st.button("⬇️ Download All", key="dl3", type="primary"):
        urls = [
            u.strip() for u in direct_input.strip().split('\n')
            if u.strip()
        ]
        if not urls:
            st.error("Paste URLs!")
        else:
            prog = st.progress(0)
            downloaded, errors = download_all(
                urls, max_workers=dw, progress_bar=prog
            )
            prog.progress(1.0, text="Done!")

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
                    z = create_zip(downloaded)
                    st.download_button(
                        f"📦 ZIP ({len(downloaded)})",
                        data=z,
                        file_name="pdfs.zip",
                        mime="application/zip",
                        type="primary"
                    )
            with d2:
                st.download_button(
                    "📝 Report",
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
    ### Smart Filtering
    The app finds ALL links then filters using
    your keywords:

    **Default:** Only keeps links with `.pdf`

    **Custom examples:**
    ```
    .pdf
    /download/
    /documents/
    getfile
    attachment
    ```

    ### If PDFs Are Missing
    1. Check "All raw links" section
    2. Find what PDF URLs look like
    3. Add the keyword to filter
    4. Click "Re-apply Filter"

    ---

    ### Scan Methods
    - **HTML Source**: Direct `<a>` tags
    - **JS Discovery**: API URLs in code
    - **Common Patterns**: CMS API guessing
    - **Sitemap**: sitemap.xml check
    """)

    st.markdown("---")
    if st.button("🗑️ Clear All"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()
