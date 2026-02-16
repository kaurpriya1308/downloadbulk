import streamlit as st
import json
import re
from datetime import datetime
from urllib.parse import unquote, urljoin
from bs4 import BeautifulSoup

# ─────────────────────────────────────────────
# Page Config
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="HAR → URL Extractor",
    page_icon="📄",
    layout="wide"
)

# ─────────────────────────────────────────────
# Session State
# ─────────────────────────────────────────────
defaults = {
    'raw_urls': [],            # all URLs from standard extraction
    'deep_urls': [],           # URLs from deep HTML/JSON parsing
    'body_texts': [],          # raw response bodies for regex
    'filtered_links': [],
    'har_loaded': False,
    'har_content_cache': None,
}
for key, val in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val if not isinstance(val, list) else []


# ─────────────────────────────────────────────
# Clean URL
# ─────────────────────────────────────────────
def clean_url(url):
    """Fix broken/escaped URLs from HAR files"""
    if not url or not isinstance(url, str):
        return ""

    cleaned = url.strip().strip('"\'')

    # Multiple passes to fix nested escaping
    for _ in range(5):
        old = cleaned
        cleaned = cleaned.replace('\\/', '/')
        cleaned = cleaned.replace('\\\\/', '/')
        cleaned = cleaned.replace('\\"', '')
        cleaned = cleaned.replace('\\n', '')
        cleaned = cleaned.replace('\\r', '')
        cleaned = cleaned.replace('\\t', '')
        cleaned = cleaned.replace('\\u0026', '&')
        cleaned = cleaned.replace('\\u003d', '=')
        cleaned = cleaned.replace('\\u003c', '<')
        cleaned = cleaned.replace('\\u003e', '>')
        if cleaned == old:
            break

    # Fix remaining backslashes before slashes
    cleaned = re.sub(r'\\+/', '/', cleaned)

    # URL decode
    if '%2F' in cleaned or '%3A' in cleaned:
        try:
            cleaned = unquote(cleaned)
        except Exception:
            pass

    # Protocol fix
    if cleaned.startswith('//'):
        cleaned = 'https:' + cleaned
    elif not cleaned.startswith('http'):
        return ""

    # Remove remaining backslashes
    cleaned = cleaned.replace('\\', '/')

    # Fix triple slashes but keep ://
    cleaned = re.sub(r'(?<!:)/{2,}', '/', cleaned)

    # Strip trailing junk
    cleaned = cleaned.rstrip('\\",;\')} \t\n\r>')

    # Remove fragment
    if '#' in cleaned:
        cleaned = cleaned.split('#')[0]

    # Final validation
    if not re.match(r'https?://.+\..+', cleaned):
        return ""

    return cleaned


# ─────────────────────────────────────────────
# Extract URLs from HTML string (any source)
# ─────────────────────────────────────────────
def extract_urls_from_html(html_string, base_url=""):
    """
    Parse an HTML string and extract URLs from:
    - <a href="...">
    - <td>https://...</td>
    - <span>https://...</span>
    - Any tag with href, src, data-href, data-src,
      data-url, data-file, data-download, action, 
      content attributes
    - onclick="window.open('...')"
    - style="background: url(...)"
    """
    urls = set()

    if not html_string or len(html_string) < 10:
        return urls

    try:
        soup = BeautifulSoup(html_string, 'html.parser')
    except Exception:
        return urls

    # ── Attributes that can hold URLs ──
    url_attributes = [
        'href', 'src', 'data-href', 'data-src',
        'data-url', 'data-file', 'data-download',
        'data-pdf', 'data-link', 'data-path',
        'data-document', 'data-attachment',
        'action', 'content', 'value',
        'data-original', 'data-source',
    ]

    # Method 1: All tags with URL-bearing attributes
    for attr in url_attributes:
        for tag in soup.find_all(attrs={attr: True}):
            val = tag.get(attr, '').strip()
            if val and not val.startswith(('#', 'javascript:', 'mailto:')):
                if val.startswith('http'):
                    urls.add(val)
                elif val.startswith('//'):
                    urls.add('https:' + val)
                elif val.startswith('/') and base_url:
                    urls.add(urljoin(base_url, val))

    # Method 2: URLs inside text content of any tag
    # Catches <td>https://example.com/file.pdf</td>
    for tag in soup.find_all(True):  # All tags
        # Direct text content (not children)
        if tag.string:
            text = tag.string.strip()
            # Find URLs in text
            found = re.findall(
                r'https?://[^\s<>"\']+',
                text
            )
            urls.update(found)

        # Also check tag's direct text parts
        for text_node in tag.find_all(string=True, recursive=False):
            text = text_node.strip()
            if text:
                found = re.findall(
                    r'https?://[^\s<>"\']+',
                    text
                )
                urls.update(found)

    # Method 3: onclick, onmousedown etc.
    event_attrs = [
        'onclick', 'onmousedown', 'onmouseup',
        'onload', 'onerror'
    ]
    for attr in event_attrs:
        for tag in soup.find_all(attrs={attr: True}):
            val = tag.get(attr, '')
            found = re.findall(
                r'["\']?(https?://[^\s"\'<>)+]+)["\']?',
                val
            )
            urls.update(found)

            # window.open('...')
            found2 = re.findall(
                r'window\.open\s*\(\s*["\']([^"\']+)["\']',
                val
            )
            urls.update(found2)

    # Method 4: style attributes with url()
    for tag in soup.find_all(style=True):
        style = tag.get('style', '')
        found = re.findall(
            r'url\s*\(\s*["\']?(https?://[^"\')\s]+)["\']?\s*\)',
            style
        )
        urls.update(found)

    return urls


# ─────────────────────────────────────────────
# Extract URLs from JSON (recursive, with HTML)
# ─────────────────────────────────────────────
def extract_urls_from_json_deep(data, base_url=""):
    """
    Recursively extract URLs from JSON data.
    
    CRITICAL: Also detects HTML strings inside JSON
    values and parses them for URLs.
    
    Example JSON that this handles:
    {
        "content": "<a href='file.pdf'>Download</a>",
        "url": "https:\\/\\/cdn.example.com\\/file.pdf",
        "items": [{"link": "/uploads/report.pdf"}]
    }
    """
    urls = set()

    def process_string(value, key=""):
        """Process a single string value"""
        if not value or not isinstance(value, str):
            return

        value = value.strip()
        if len(value) < 4:
            return

        # ── Check if value IS a URL ──
        if value.startswith(('http://', 'https://', '//')):
            urls.add(value)

        # Relative path that looks like a file
        elif value.startswith('/') and '.' in value.split('/')[-1]:
            if base_url:
                urls.add(urljoin(base_url, value))

        # ── Check if value CONTAINS URLs ──
        # Normal URLs
        found = re.findall(
            r'https?://[^\s"\'<>\\,;\]})]+',
            value
        )
        urls.update(found)

        # Escaped URLs
        found_esc = re.findall(
            r'https?:\\{1,4}/\\{0,4}/[^\s"\'<>,;\]})]+',
            value
        )
        urls.update(found_esc)

        # ── Check if value contains HTML ──
        # This is the KEY feature for sites like Shriram Finance
        # where API returns HTML fragments as JSON string values
        if any(marker in value for marker in [
            '<a ', '<a\n', '<td', '<div', '<span',
            '<p ', '<li', '<tr', 'href=', 'src=',
            '<table', '<ul', '<ol', '<iframe',
            '<embed', '<object',
        ]):
            html_urls = extract_urls_from_html(value, base_url)
            urls.update(html_urls)

    def recurse(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str):
                    process_string(value, key)
                else:
                    recurse(value)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, str):
                    process_string(item)
                else:
                    recurse(item)
        elif isinstance(obj, str):
            process_string(obj)

    recurse(data)
    return urls


# ─────────────────────────────────────────────
# MAIN: Extract everything from HAR
# ─────────────────────────────────────────────
def extract_all_from_har(har_content):
    """
    Extract ALL URLs from HAR file using multiple methods:
    
    1. Request URLs
    2. Response headers
    3. Response bodies — parsed as:
       a. JSON → recursive extraction + HTML-in-JSON
       b. HTML → full BeautifulSoup parse
       c. JavaScript → regex extraction
       d. Any text → regex extraction
    4. POST data
    5. Regex on raw body text for custom patterns
    
    Returns: (all_urls, body_texts)
      - all_urls: set of extracted URLs
      - body_texts: list of (mime_type, body) for regex matching
    """
    all_urls = set()
    body_texts = []  # Store bodies for custom regex later

    try:
        har_data = json.loads(har_content)
    except json.JSONDecodeError as e:
        st.error(f"Invalid HAR file: {e}")
        return set(), []

    entries = har_data.get('log', {}).get('entries', [])
    if not entries:
        st.error("No entries found in HAR file")
        return set(), []

    for entry in entries:
        request = entry.get('request', {})
        response = entry.get('response', {})

        # Determine base URL from request
        req_url = request.get('url', '')
        if req_url:
            all_urls.add(req_url)
            try:
                from urllib.parse import urlparse as _urlparse
                _p = _urlparse(req_url)
                base_url = f"{_p.scheme}://{_p.netloc}"
            except Exception:
                base_url = ""
        else:
            base_url = ""

        # ── Request headers ──
        for header in request.get('headers', []):
            val = header.get('value', '')
            if 'http' in val.lower():
                found = re.findall(
                    r'https?://[^\s"\'<>\\,;]+', val
                )
                all_urls.update(found)

        # ── POST data ──
        post_text = request.get('postData', {}).get('text', '')
        if post_text:
            found = re.findall(
                r'https?://[^\s"\'<>\\,;]+', post_text
            )
            all_urls.update(found)
            found_esc = re.findall(
                r'https?:\\{1,4}/\\{0,4}/[^\s"\'<>,;]+', post_text
            )
            all_urls.update(found_esc)

        # ── Response headers ──
        for header in response.get('headers', []):
            name = header.get('name', '').lower()
            val = header.get('value', '')
            if name in [
                'location', 'content-location', 'link',
                'x-redirect', 'refresh'
            ]:
                found = re.findall(
                    r'https?://[^\s"\'<>;]+', val
                )
                all_urls.update(found)

        # ── Response body ──
        content = response.get('content', {})
        body = content.get('text', '')
        if not body:
            continue

        mime = content.get('mimeType', '').lower()

        # Store body for custom regex later
        body_texts.append((mime, req_url, body))

        # ── Parse based on content type ──

        # JSON response
        if ('json' in mime
                or body.strip().startswith(('{', '['))):
            try:
                data = json.loads(body)
                json_urls = extract_urls_from_json_deep(
                    data, base_url
                )
                all_urls.update(json_urls)
            except json.JSONDecodeError:
                pass

            # Also regex on raw JSON text
            found = re.findall(
                r'https?://[^\s"\'<>\\,;\]})]+', body
            )
            all_urls.update(found)
            found_esc = re.findall(
                r'https?:\\{1,4}/\\{0,4}/[^\s"\'<>,;\]})]+',
                body
            )
            all_urls.update(found_esc)

        # HTML response
        elif 'html' in mime:
            html_urls = extract_urls_from_html(body, base_url)
            all_urls.update(html_urls)

            # Also regex
            found = re.findall(
                r'https?://[^\s"\'<>]+', body
            )
            all_urls.update(found)

        # JavaScript
        elif 'javascript' in mime or 'script' in mime:
            found = re.findall(
                r'https?://[^\s"\'<>\\,;]+', body
            )
            all_urls.update(found)
            found_esc = re.findall(
                r'https?:\\{1,4}/\\{0,4}/[^\s"\'<>,;]+',
                body
            )
            all_urls.update(found_esc)

        # XML / RSS / Atom
        elif 'xml' in mime:
            found = re.findall(
                r'https?://[^\s"\'<>]+', body
            )
            all_urls.update(found)

        # Anything else with text
        else:
            if isinstance(body, str) and len(body) > 10:
                found = re.findall(
                    r'https?://[^\s"\'<>]+', body
                )
                all_urls.update(found)

    return all_urls, body_texts


# ─────────────────────────────────────────────
# Apply custom regex on raw HAR bodies
# ─────────────────────────────────────────────
def apply_custom_regex(body_texts, regex_pattern):
    """
    Run a user-provided regex against ALL response
    bodies in the HAR file.
    
    This lets users find URLs that standard extraction
    might miss, using patterns like:
    - https://.*\\.pdf
    - href="([^"]*\\.pdf)"
    - <td[^>]*>([^<]*\\.pdf[^<]*)</td>
    """
    matches = set()

    try:
        compiled = re.compile(regex_pattern, re.IGNORECASE)
    except re.error as e:
        st.error(f"Invalid regex: {e}")
        return matches

    for mime, req_url, body in body_texts:
        if not body:
            continue

        found = compiled.findall(body)
        for match in found:
            # findall returns groups if pattern has groups
            if isinstance(match, tuple):
                for m in match:
                    if m:
                        matches.add(m)
            else:
                if match:
                    matches.add(match)

    return matches


# ─────────────────────────────────────────────
# Filter and clean URLs
# ─────────────────────────────────────────────
def filter_urls(all_urls, include_keywords, exclude_keywords):
    """
    Filter URLs by include/exclude keywords.
    Keywords support simple string matching (not regex).
    """
    results = []
    seen = set()

    inc_kws = [
        kw.strip().lower() for kw in include_keywords if kw.strip()
    ]
    exc_kws = [
        kw.strip().lower() for kw in exclude_keywords if kw.strip()
    ]

    # Always exclude these
    auto_exclude = [
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp',
        '.ico', '.bmp', '.tiff',
        '.css', '.woff', '.woff2', '.ttf', '.eot',
        '.mp4', '.mp3', '.avi', '.mov', '.webm',
        'google-analytics.com', 'googletagmanager.com',
        'facebook.com/tr', 'doubleclick.net',
        'pixel', 'beacon', 'tracker',
    ]
    all_exc = exc_kws + auto_exclude

    for raw_url in all_urls:
        cleaned = clean_url(raw_url)
        if not cleaned:
            continue
        if cleaned in seen:
            continue

        cleaned_lower = cleaned.lower()

        # Exclude check
        if any(exc in cleaned_lower for exc in all_exc):
            continue

        # Include check — must match at least one keyword
        if inc_kws:
            matched = None
            for kw in inc_kws:
                if kw in cleaned_lower:
                    matched = kw
                    break
            if not matched:
                continue
        else:
            matched = "no-filter"

        seen.add(cleaned)
        results.append((cleaned, matched))

    results.sort(key=lambda x: x[0].split('/')[-1].lower())
    return results


# ─────────────────────────────────────────────
# Generate TXT
# ─────────────────────────────────────────────
def generate_txt(results, source, inc_kw, exc_kw,
                 html_regex="", pdf_regex=""):
    lines = [
        "=" * 70,
        "URL EXTRACTION REPORT",
        "=" * 70,
        f"Source       : {source}",
        f"Date         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total URLs   : {len(results)}",
        f"Include      : {', '.join(inc_kw)}",
        f"Exclude      : {len(exc_kw)} patterns",
    ]
    if pdf_regex:
        lines.append(f"PDF Regex    : {pdf_regex}")
    if html_regex:
        lines.append(f"HTML Regex   : {html_regex}")

    lines.extend(["=" * 70, "", "── EXTRACTED URLS ──", ""])

    for i, (url, kw) in enumerate(results, 1):
        fname = url.split('/')[-1].split('?')[0]
        lines.append(f"{i:4d}. {fname}")
        lines.append(f"      {url}")
        lines.append(f"      [matched: {kw}]")
        lines.append("")

    lines.extend(["=" * 70, "", "── PLAIN URL LIST ──", ""])
    for url, _ in results:
        lines.append(url)

    lines.extend(["", "=" * 70, "END"])
    return "\n".join(lines)


# ═════════════════════════════════════════════
# STREAMLIT UI
# ═════════════════════════════════════════════

st.title("📄 HAR File → URL Extractor")
st.markdown(
    "Upload `.har` file → Extract **PDF links, HTML links, "
    "or any URL** using keywords + regex → Download as `.txt`"
)

# ── How-to ──
with st.expander("📖 How to capture a .har file", expanded=False):
    st.markdown("""
    1. **Open Chrome** → go to target website
    2. **Press F12** → **Network** tab
    3. **Check "Preserve log"**
    4. **Click ALL tabs/buttons** on the page
    5. **Right-click** in Network list → **Save all as HAR with content**
    6. **Upload** that `.har` file below
    """)

st.markdown("---")

# ─────────────────────────────────────────────
# FILE UPLOAD
# ─────────────────────────────────────────────
uploaded_file = st.file_uploader(
    "📁 Upload .har file",
    type=['har'],
    help="From Chrome DevTools → Network → Save all as HAR"
)

# ─────────────────────────────────────────────
# FILTER SETTINGS
# ─────────────────────────────────────────────
st.markdown("---")
st.subheader("🔧 Extraction Settings")

# Row 1: Keywords
kw_col1, kw_col2 = st.columns(2)

with kw_col1:
    st.markdown("**✅ Include Keywords** (URL must contain ≥1)")
    include_input = st.text_input(
        "Include keywords (separate with |)",
        value=".pdf",
        placeholder=".pdf|/download/|getfile",
        help=(
            "URL must contain at least ONE of these.\n"
            "Examples: .pdf | .pdf|.xlsx | .pdf|/documents/"
        ),
        key="include_kw"
    )

with kw_col2:
    st.markdown("**❌ Exclude Keywords** (URL must NOT contain)")
    exclude_input = st.text_input(
        "Exclude keywords (separate with |)",
        value=".jpg|.jpeg|.png|.gif|.svg|.webp|.ico|.css|.woff|.woff2",
        placeholder=".jpg|.png|facebook",
        key="exclude_kw"
    )

# Row 2: Regex patterns
st.markdown("---")
st.subheader("🔍 Regex Patterns (Advanced)")
st.caption(
    "Run regex directly on raw HAR response bodies. "
    "Finds URLs that keyword filtering might miss. "
    "Use capture groups `()` to extract the URL part."
)

rx_col1, rx_col2 = st.columns(2)

with rx_col1:
    st.markdown("**📄 PDF/Document URL Regex**")
    pdf_regex = st.text_input(
        "PDF regex pattern",
        value="",
        placeholder=r'https?://[^\s"\\]+\.pdf[^\s"\\]*',
        help=(
            "Examples:\n\n"
            r'`https?://[^\s"\\]+\.pdf[^\s"\\]*`'
            " — any URL ending in .pdf\n\n"
            r'`https?://cdn\.example\.com/[^\s"\\]+\.pdf`'
            " — PDFs from specific CDN\n\n"
            r'`"file_url"\s*:\s*"([^"]+\.pdf[^"]*)`'
            " — PDF URL from JSON key\n\n"
            r'`/uploads/[^\s"\\]+\.pdf`'
            " — relative PDF paths"
        ),
        key="pdf_regex"
    )

with rx_col2:
    st.markdown("**🌐 HTML/Page URL Regex**")
    html_regex = st.text_input(
        "HTML link regex pattern",
        value="",
        placeholder=r'href=["\']([^"\']+)["\']',
        help=(
            "Examples:\n\n"
            r'`href=["\']([^"\']+)["\']`'
            " — all href values\n\n"
            r'`href=["\']([^"\']*investor[^"\']*)["\']`'
            " — hrefs containing 'investor'\n\n"
            r'`<td[^>]*>\s*(https?://[^<]+)\s*</td>`'
            " — URLs inside <td> tags\n\n"
            r'`<a[^>]+href=["\']([^"\']+\.pdf)["\']`'
            " — PDF links in anchor tags\n\n"
            r'`data-url=["\']([^"\']+)["\']`'
            " — data-url attribute values\n\n"
            r'`window\.open\(["\']([^"\']+)["\']`'
            " — JavaScript window.open URLs"
        ),
        key="html_regex"
    )

# Parse keywords
include_keywords = [
    kw.strip() for kw in include_input.split('|') if kw.strip()
]
exclude_keywords = [
    kw.strip() for kw in exclude_input.split('|') if kw.strip()
]

# Active filter summary
filter_parts = []
if include_keywords:
    filter_parts.append(f"Keywords: `{include_keywords}`")
if pdf_regex.strip():
    filter_parts.append(f"PDF regex: `{pdf_regex}`")
if html_regex.strip():
    filter_parts.append(f"HTML regex: `{html_regex}`")

st.info(
    f"**Active filters:** {' | '.join(filter_parts) if filter_parts else 'None'} "
    f"| Excluding: `{len(exclude_keywords)}` patterns"
)

# ─────────────────────────────────────────────
# PROCESS
# ─────────────────────────────────────────────
st.markdown("---")

if uploaded_file:
    try:
        har_content = uploaded_file.read().decode('utf-8')
    except UnicodeDecodeError:
        har_content = uploaded_file.read().decode(
            'utf-8', errors='ignore'
        )

    st.session_state.har_content_cache = har_content
    file_mb = len(har_content) / (1024 * 1024)
    st.caption(f"📁 {uploaded_file.name} | {file_mb:.1f} MB")

    if st.button(
        "🚀 Extract URLs", type="primary", key="extract"
    ):
        with st.spinner("Parsing HAR file..."):
            # ── Step 1: Standard + deep extraction ──
            all_urls, body_texts = extract_all_from_har(har_content)
            st.session_state.body_texts = body_texts

            # ── Step 2: Apply custom regex on raw bodies ──
            regex_urls = set()

            if pdf_regex.strip():
                with st.spinner("Applying PDF regex..."):
                    pdf_matches = apply_custom_regex(
                        body_texts, pdf_regex.strip()
                    )
                    regex_urls.update(pdf_matches)
                    st.info(
                        f"PDF regex matched {len(pdf_matches)} items"
                    )

            if html_regex.strip():
                with st.spinner("Applying HTML regex..."):
                    html_matches = apply_custom_regex(
                        body_texts, html_regex.strip()
                    )
                    regex_urls.update(html_matches)
                    st.info(
                        f"HTML regex matched {len(html_matches)} items"
                    )

            # Combine all sources
            combined = all_urls | regex_urls
            st.session_state.raw_urls = sorted(list(combined))

            # ── Step 3: Filter ──
            # For regex results, add them directly
            # (they already matched user's pattern)
            filtered = filter_urls(
                combined, include_keywords, exclude_keywords
            )

            # Also add cleaned regex results that might not
            # match keywords but DID match regex
            if regex_urls:
                existing = {url for url, _ in filtered}
                for raw in regex_urls:
                    cleaned = clean_url(raw)
                    if cleaned and cleaned not in existing:
                        # Check exclusions only
                        exc_lower = [
                            e.lower() for e in exclude_keywords
                        ]
                        if not any(
                            e in cleaned.lower() for e in exc_lower
                        ):
                            source = "pdf-regex" if pdf_regex else "html-regex"
                            filtered.append((cleaned, source))
                            existing.add(cleaned)

            st.session_state.filtered_links = filtered
            st.session_state.har_loaded = True

        # Metrics
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("🔗 Total Raw URLs", len(combined))
        with m2:
            st.metric("📄 After Filtering", len(filtered))
        with m3:
            st.metric(
                "🔍 Regex Matches",
                len(regex_urls) if regex_urls else 0
            )
        with m4:
            st.metric(
                "🚫 Excluded",
                len(combined) - len(filtered)
            )


# ─────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────
if st.session_state.har_loaded and st.session_state.filtered_links:
    st.markdown("---")
    count = len(st.session_state.filtered_links)
    st.header(f"📄 {count} URLs Extracted")

    # Re-filter button
    if st.button("🔄 Re-apply Filters", key="refilter"):
        # Re-run regex if bodies are cached
        regex_urls = set()
        if pdf_regex.strip() and st.session_state.body_texts:
            regex_urls.update(
                apply_custom_regex(
                    st.session_state.body_texts,
                    pdf_regex.strip()
                )
            )
        if html_regex.strip() and st.session_state.body_texts:
            regex_urls.update(
                apply_custom_regex(
                    st.session_state.body_texts,
                    html_regex.strip()
                )
            )

        combined = set(st.session_state.raw_urls) | regex_urls
        filtered = filter_urls(
            combined, include_keywords, exclude_keywords
        )

        if regex_urls:
            existing = {u for u, _ in filtered}
            exc_lower = [e.lower() for e in exclude_keywords]
            for raw in regex_urls:
                cleaned = clean_url(raw)
                if cleaned and cleaned not in existing:
                    if not any(
                        e in cleaned.lower() for e in exc_lower
                    ):
                        filtered.append((cleaned, "regex"))
                        existing.add(cleaned)

        st.session_state.filtered_links = filtered
        st.rerun()

    # Display
    st.markdown("### Extracted URLs:")

    for i, (url, kw) in enumerate(
        st.session_state.filtered_links, 1
    ):
        fname = url.split('/')[-1].split('?')[0]
        if len(fname) > 80:
            fname = fname[:77] + "..."

        c1, c2, c3, c4 = st.columns([0.4, 2.5, 5, 1.5])
        with c1:
            st.text(f"{i:3d}.")
        with c2:
            st.text(f"📄 {fname}")
        with c3:
            st.markdown(f"[Open Link]({url})")
        with c4:
            st.caption(f"via: {kw}")

    # ── Downloads ──
    st.markdown("---")
    st.header("⬇️ Download")

    d1, d2, d3 = st.columns(3)

    with d1:
        plain = "\n".join(
            u for u, _ in st.session_state.filtered_links
        )
        st.download_button(
            "📝 URLs Only (.txt)",
            data=plain,
            file_name=(
                f"urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            ),
            mime="text/plain",
            type="primary"
        )

    with d2:
        report = generate_txt(
            st.session_state.filtered_links,
            uploaded_file.name if uploaded_file else "unknown",
            include_keywords, exclude_keywords,
            html_regex, pdf_regex
        )
        st.download_button(
            "📋 Full Report (.txt)",
            data=report,
            file_name=(
                f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            ),
            mime="text/plain"
        )

    with d3:
        csv_lines = ["index,filename,url,matched_by"]
        for i, (url, kw) in enumerate(
            st.session_state.filtered_links, 1
        ):
            fn = url.split('/')[-1].split('?')[0].replace(',', '_')
            csv_lines.append(f'{i},"{fn}","{url}","{kw}"')
        st.download_button(
            "📊 CSV (.csv)",
            data="\n".join(csv_lines),
            file_name=(
                f"urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            ),
            mime="text/csv"
        )

    # Copy-paste box
    st.markdown("---")
    st.subheader("📋 Copy-Paste")
    st.text_area(
        "All URLs",
        value="\n".join(
            u for u, _ in st.session_state.filtered_links
        ),
        height=250,
        key="copy_box"
    )


# ─────────────────────────────────────────────
# DEBUG
# ─────────────────────────────────────────────
if st.session_state.har_loaded:

    # Raw URL search
    with st.expander(
        f"🔧 Debug: {len(st.session_state.raw_urls)} raw URLs"
    ):
        st.caption(
            "Search here if URLs are missing. "
            "Then adjust keywords or regex above."
        )

        search = st.text_input(
            "🔍 Search",
            placeholder="pdf, report, annual, download...",
            key="search_raw"
        )

        show_urls = st.session_state.raw_urls
        if search:
            show_urls = [
                u for u in show_urls
                if search.lower() in u.lower()
            ]
            st.caption(f"{len(show_urls)} matches for '{search}'")

        for i, url in enumerate(show_urls[:500], 1):
            cleaned = clean_url(url)
            if cleaned:
                is_match = any(
                    kw.lower() in cleaned.lower()
                    for kw in include_keywords
                )
                icon = "📄" if is_match else "🔗"
                st.text(f"{icon} {i}. {cleaned[:150]}")

    # Response body search
    if st.session_state.body_texts:
        with st.expander("🔧 Debug: Search Response Bodies"):
            st.caption(
                "Search inside actual response content. "
                "Useful for finding the right regex pattern."
            )

            body_search = st.text_input(
                "🔍 Search in response bodies",
                placeholder=".pdf, href, <td, document",
                key="body_search"
            )

            if body_search:
                match_count = 0
                for mime, req_url, body in st.session_state.body_texts:
                    if body_search.lower() in body.lower():
                        match_count += 1
                        with st.expander(
                            f"📡 {mime[:30]} | {req_url[:80]}"
                        ):
                            # Find and highlight matches
                            idx = body.lower().find(
                                body_search.lower()
                            )
                            if idx >= 0:
                                start = max(0, idx - 200)
                                end = min(len(body), idx + 500)
                                snippet = body[start:end]
                                st.code(snippet, language="text")
                            else:
                                st.code(
                                    body[:500], language="text"
                                )

                            if match_count >= 20:
                                break

                st.caption(
                    f"Found '{body_search}' in "
                    f"{match_count} responses"
                )


# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.header("📖 Guide")

    st.markdown("""
    ### Extraction Methods
    
    **1. Keywords (simple)**
    ```
    .pdf          → URLs with .pdf
    .pdf|.xlsx    → PDFs and Excel files
    /investor/    → investor path URLs
    ```

    **2. PDF Regex (advanced)**
    Find PDFs even in complex JSON:
    """)

    st.code(
        r'https?://[^\s"\\]+\.pdf[^\s"\\]*',
        language="text"
    )
    st.code(
        r'"file_url"\s*:\s*"([^"]+\.pdf)',
        language="text"
    )
    st.code(
        r'/uploads/[^\s"\\]+\.pdf',
        language="text"
    )

    st.markdown("""
    **3. HTML Regex (advanced)**
    Extract from HTML inside JSON:
    """)

    st.code(
        r'href=["\']([^"\']+\.pdf[^"\']*)["\']',
        language="text"
    )
    st.code(
        r'<td[^>]*>\s*(https?://[^<]+)\s*</td>',
        language="text"
    )
    st.code(
        r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>',
        language="text"
    )
    st.code(
        r'data-url=["\']([^"\']+)["\']',
        language="text"
    )

    st.markdown("""
    ---
    
    ### What Gets Parsed
    
    - ✅ JSON response bodies
    - ✅ **HTML inside JSON** values
    - ✅ HTML response bodies
    - ✅ JavaScript files
    - ✅ All HTML attributes
      (`href`, `src`, `data-*`, `onclick`)
    - ✅ Text inside `<td>`, `<span>`, `<div>`
    - ✅ POST request data
    - ✅ Redirect headers
    - ✅ Escaped URLs (`\\/\\/`)
    
    ---
    
    ### Debugging Tips
    
    1. Check **"Debug: raw URLs"** section
    2. **Search response bodies** for 
       patterns you see in DevTools
    3. Build regex based on what you find
    4. Click **Re-apply Filters**
    """)

    st.markdown("---")
    if st.button("🗑️ Clear All"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()
