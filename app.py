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
    'filtered_links': [],
    'regex_matches': [],       # only regex-matched items
    'keyword_matches': [],     # only keyword-matched items
    'body_texts': [],
    'har_loaded': False,
    'extraction_log': [],      # what happened during extraction
}
for key, val in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = []


# ─────────────────────────────────────────────
# Unescape JSON string content
# ─────────────────────────────────────────────
def unescape_json_string(text):
    """
    Unescape a string that was inside a JSON value.
    
    HAR files store response bodies as JSON strings,
    so HTML inside JSON gets double-escaped:
    
    Original HTML:
      <a href="https://example.com/file.pdf">
    
    Inside JSON:
      "text": "<a href=\\\"https:\\/\\/example.com\\/file.pdf\\\">"
    
    This function reverses ALL that escaping.
    """
    if not text or not isinstance(text, str):
        return ""

    s = text

    # Step 1: Handle JSON unicode escapes
    s = s.replace('\\u003c', '<')
    s = s.replace('\\u003e', '>')
    s = s.replace('\\u0026', '&')
    s = s.replace('\\u003d', '=')
    s = s.replace('\\u0022', '"')
    s = s.replace('\\u0027', "'")

    # Step 2: Unescape JSON string escapes (multiple passes)
    for _ in range(5):
        old = s
        s = s.replace('\\"', '"')
        s = s.replace('\\/', '/')
        s = s.replace('\\\\', '\\')
        s = s.replace('\\n', '\n')
        s = s.replace('\\r', '\r')
        s = s.replace('\\t', '\t')
        if s == old:
            break

    # Step 3: Fix any remaining escaped slashes
    s = re.sub(r'\\+/', '/', s)

    # Step 4: Remove leading/trailing quotes that
    # sometimes wrap the entire body
    s = s.strip()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]

    return s


# ─────────────────────────────────────────────
# Clean a single URL
# ─────────────────────────────────────────────
def clean_url(url):
    """Fix broken/escaped URLs"""
    if not url or not isinstance(url, str):
        return ""

    cleaned = url.strip().strip('"\'')

    # Unescape
    for _ in range(5):
        old = cleaned
        cleaned = cleaned.replace('\\/', '/')
        cleaned = cleaned.replace('\\\\/', '/')
        cleaned = cleaned.replace('\\"', '')
        cleaned = cleaned.replace('\\n', '')
        cleaned = cleaned.replace('\\r', '')
        cleaned = cleaned.replace('\\t', '')
        cleaned = cleaned.replace('\\u0026', '&')
        if cleaned == old:
            break

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

    cleaned = cleaned.replace('\\', '/')
    cleaned = re.sub(r'(?<!:)/{2,}', '/', cleaned)
    cleaned = cleaned.rstrip('\\",;\')} \t\n\r>')

    # Remove fragment
    if '#' in cleaned:
        cleaned = cleaned.split('#')[0]

    # Basic validation
    if not re.match(r'https?://.+\..+', cleaned):
        return ""

    return cleaned


# ─────────────────────────────────────────────
# Extract URLs from HTML string
# ─────────────────────────────────────────────
def extract_urls_from_html(html_string, base_url=""):
    """
    Parse HTML and extract URLs from ALL possible locations:
    - <a href>, <img src>, <embed src>, etc.
    - <td>, <span>, <div> text content
    - onclick, data-* attributes
    - style background-url
    """
    urls = set()
    if not html_string or len(html_string) < 10:
        return urls

    try:
        soup = BeautifulSoup(html_string, 'html.parser')
    except Exception:
        return urls

    # Attributes that hold URLs
    url_attrs = [
        'href', 'src', 'data-href', 'data-src',
        'data-url', 'data-file', 'data-download',
        'data-pdf', 'data-link', 'data-path',
        'data-document', 'action', 'content', 'value',
    ]

    for attr in url_attrs:
        for tag in soup.find_all(attrs={attr: True}):
            val = tag.get(attr, '').strip()
            if val and not val.startswith(
                ('#', 'javascript:', 'mailto:')
            ):
                if val.startswith('http'):
                    urls.add(val)
                elif val.startswith('//'):
                    urls.add('https:' + val)
                elif val.startswith('/') and base_url:
                    urls.add(urljoin(base_url, val))

    # URLs in text content of any tag
    for tag in soup.find_all(True):
        if tag.string:
            found = re.findall(
                r'https?://[^\s<>"\']+', tag.string
            )
            urls.update(found)

    # onclick handlers
    for attr in ['onclick', 'onmousedown']:
        for tag in soup.find_all(attrs={attr: True}):
            val = tag.get(attr, '')
            found = re.findall(
                r'["\']?(https?://[^\s"\'<>)]+)["\']?', val
            )
            urls.update(found)
            found2 = re.findall(
                r'window\.open\s*\(\s*["\']([^"\']+)', val
            )
            urls.update(found2)

    return urls


# ─────────────────────────────────────────────
# MAIN: Parse HAR and collect body texts
# ─────────────────────────────────────────────
def parse_har_bodies(har_content):
    """
    Parse HAR file and return list of
    (mime_type, request_url, UNESCAPED body text).
    
    KEY: Bodies are unescaped BEFORE storing,
    so HTML inside JSON becomes parseable HTML.
    """
    bodies = []
    log = []

    try:
        har_data = json.loads(har_content)
    except json.JSONDecodeError as e:
        st.error(f"Invalid HAR file: {e}")
        return [], log

    entries = har_data.get('log', {}).get('entries', [])
    if not entries:
        st.error("No entries found in HAR file")
        return [], log

    log.append(f"HAR file has {len(entries)} entries")

    for entry in entries:
        request = entry.get('request', {})
        response = entry.get('response', {})
        req_url = request.get('url', '')
        content = response.get('content', {})
        body = content.get('text', '')

        if not body or len(body) < 20:
            continue

        mime = content.get('mimeType', '').lower()

        # ── CRITICAL: Unescape the body ──
        # HAR stores body as JSON string value, so HTML
        # like <a href="..."> becomes <a href=\\\"...\\\">
        # We must unescape it to get real HTML
        unescaped = unescape_json_string(body)

        bodies.append((mime, req_url, unescaped))

        # For JSON bodies, also try to parse and extract
        # HTML values from within the JSON
        if ('json' in mime
                or unescaped.strip().startswith(('{', '['))):
            try:
                data = json.loads(unescaped)
                html_fragments = extract_html_from_json(data)
                for fragment in html_fragments:
                    # Each fragment is already unescaped by
                    # json.loads, but might still need cleanup
                    clean_fragment = unescape_json_string(fragment)
                    if '<' in clean_fragment and '>' in clean_fragment:
                        bodies.append((
                            'text/html (from json)',
                            req_url,
                            clean_fragment
                        ))
            except json.JSONDecodeError:
                pass

    log.append(
        f"Collected {len(bodies)} response bodies "
        f"(including HTML extracted from JSON)"
    )
    return bodies, log


def extract_html_from_json(data):
    """
    Recursively find string values in JSON that contain HTML.
    Returns list of HTML strings.
    """
    html_strings = []

    def recurse(obj):
        if isinstance(obj, dict):
            for value in obj.values():
                if isinstance(value, str):
                    check(value)
                else:
                    recurse(value)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, str):
                    check(item)
                else:
                    recurse(item)

    def check(value):
        if not value or len(value) < 20:
            return
        # Does this string contain HTML?
        html_indicators = [
            '<a ', '<a\n', '<a\t', '<div', '<span',
            '<td', '<tr', '<table', '<p ', '<p>',
            '<li', '<ul', '<ol', '<article',
            '<section', '<iframe', '<embed',
            'href=', 'src=',
        ]
        value_lower = value.lower()
        if any(ind in value_lower for ind in html_indicators):
            html_strings.append(value)

    recurse(data)
    return html_strings


# ─────────────────────────────────────────────
# Apply regex on bodies
# ─────────────────────────────────────────────
def apply_regex(bodies, pattern):
    """
    Run regex on all response bodies.
    Returns list of (matched_string, source_url, mime).
    """
    results = []
    seen = set()

    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        st.error(f"Invalid regex: {e}")
        return results

    for mime, req_url, body in bodies:
        if not body:
            continue

        found = compiled.findall(body)
        for match in found:
            # Handle groups
            if isinstance(match, tuple):
                for m in match:
                    if m and m not in seen:
                        seen.add(m)
                        results.append((m, req_url, mime))
            else:
                if match and match not in seen:
                    seen.add(match)
                    results.append((match, req_url, mime))

    return results


# ─────────────────────────────────────────────
# Apply keyword filter on bodies
# ─────────────────────────────────────────────
def apply_keyword_filter(bodies, include_keywords, exclude_keywords):
    """
    Extract URLs from bodies that match include keywords.
    
    Process:
    1. For each body, extract ALL URLs (from HTML + raw regex)
    2. Clean each URL
    3. Keep only those matching include keywords
    4. Remove those matching exclude keywords
    """
    results = []
    seen = set()

    inc_kws = [kw.strip().lower() for kw in include_keywords if kw.strip()]
    exc_kws = [kw.strip().lower() for kw in exclude_keywords if kw.strip()]

    # Auto-exclude
    auto_exc = [
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp',
        '.ico', '.bmp', '.css', '.woff', '.woff2', '.ttf',
        '.eot', '.mp4', '.mp3', '.avi', '.webm',
        'google-analytics', 'googletagmanager',
        'facebook.com/tr', 'doubleclick.net',
    ]
    all_exc = exc_kws + auto_exc

    for mime, req_url, body in bodies:
        if not body:
            continue

        found_urls = set()

        # Determine base URL
        try:
            from urllib.parse import urlparse as _up
            _p = _up(req_url)
            base = f"{_p.scheme}://{_p.netloc}" if _p.scheme else ""
        except Exception:
            base = ""

        # Extract URLs based on content type
        if '<' in body and '>' in body:
            # Has HTML — parse it
            html_urls = extract_urls_from_html(body, base)
            found_urls.update(html_urls)

        # Also regex extract from raw text
        raw_urls = re.findall(
            r'https?://[^\s"\'<>\\,;\]})]+', body
        )
        found_urls.update(raw_urls)

        # Filter each URL
        for raw_url in found_urls:
            cleaned = clean_url(raw_url)
            if not cleaned or cleaned in seen:
                continue

            cl = cleaned.lower()

            # Exclude check
            if any(e in cl for e in all_exc):
                continue

            # Include check
            matched = None
            for kw in inc_kws:
                if kw in cl:
                    matched = kw
                    break

            if matched:
                seen.add(cleaned)
                results.append((cleaned, matched, req_url))

    results.sort(key=lambda x: x[0].split('/')[-1].lower())
    return results


# ─────────────────────────────────────────────
# Generate TXT
# ─────────────────────────────────────────────
def generate_txt(results, source, inc_kw, exc_kw,
                 pdf_regex="", html_regex=""):
    lines = [
        "=" * 70,
        "URL EXTRACTION REPORT",
        "=" * 70,
        f"Source       : {source}",
        f"Date         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total URLs   : {len(results)}",
        f"Include      : {', '.join(inc_kw) if inc_kw else 'none'}",
        f"Exclude      : {len(exc_kw)} patterns",
    ]
    if pdf_regex:
        lines.append(f"PDF Regex    : {pdf_regex}")
    if html_regex:
        lines.append(f"HTML Regex   : {html_regex}")

    lines.extend(["=" * 70, "", "── EXTRACTED URLS ──", ""])

    for i, item in enumerate(results, 1):
        url = item[0]
        matched_by = item[1]
        fname = url.split('/')[-1].split('?')[0]
        lines.append(f"{i:4d}. {fname}")
        lines.append(f"      {url}")
        lines.append(f"      [matched: {matched_by}]")
        lines.append("")

    lines.extend(["=" * 70, "", "── PLAIN URL LIST ──", ""])
    for item in results:
        lines.append(item[0])

    lines.extend(["", "=" * 70, "END"])
    return "\n".join(lines)


# ═════════════════════════════════════════════
# STREAMLIT UI
# ═════════════════════════════════════════════

st.title("📄 HAR File → URL Extractor")
st.markdown(
    "Upload `.har` → Extract **PDF links, HTML page links, "
    "or any URL** using keywords + regex"
)

with st.expander("📖 How to capture .har file"):
    st.markdown("""
    1. Open Chrome → target website
    2. F12 → Network tab → Check **"Preserve log"**
    3. **Click ALL tabs/buttons** on the page
    4. Right-click Network list → **Save all as HAR with content**
    5. Upload here
    """)

st.markdown("---")

# ─────────────────────────────────────────────
# UPLOAD
# ─────────────────────────────────────────────
uploaded_file = st.file_uploader(
    "📁 Upload .har file", type=['har']
)

# ─────────────────────────────────────────────
# FILTER SETTINGS
# ─────────────────────────────────────────────
st.markdown("---")
st.subheader("🔧 Extraction Settings")

st.markdown(
    "**Use Keywords OR Regex or BOTH.** "
    "Results from all methods are combined."
)

# Keywords
kw1, kw2 = st.columns(2)
with kw1:
    st.markdown("**✅ Include Keywords** — URL must contain ≥1")
    include_input = st.text_input(
        "Include (separate with |)",
        value=".pdf",
        placeholder=".pdf|/download/|.xlsx",
        key="inc"
    )
with kw2:
    st.markdown("**❌ Exclude Keywords** — URL must NOT contain")
    exclude_input = st.text_input(
        "Exclude (separate with |)",
        value=".jpg|.jpeg|.png|.gif|.svg|.webp|.ico|.css|.woff|.woff2",
        placeholder=".jpg|.png|facebook",
        key="exc"
    )

# Regex
st.markdown("---")
st.subheader("🔍 Regex Patterns")
st.caption(
    "Regex runs on **unescaped** response bodies. "
    "Use `()` capture group to extract the URL part. "
    "Leave blank to skip."
)

rx1, rx2 = st.columns(2)
with rx1:
    st.markdown("**📄 PDF / Document Regex**")
    pdf_regex = st.text_input(
        "PDF regex",
        value="",
        placeholder=r'https?://[^\s"<>]+\.pdf[^\s"<>]*',
        help=(
            "Runs on raw response text.\n\n"
            "Examples:\n"
            r'`https?://[^\s"<>]+\.pdf`' " — any PDF URL\n\n"
            r'`href="([^"]+\.pdf[^"]*)`' " — PDF in href\n\n"
            r'`"url"\s*:\s*"([^"]+\.pdf)`' " — PDF in JSON"
        ),
        key="pdf_rx"
    )

with rx2:
    st.markdown("**🌐 HTML / Page Link Regex**")
    html_regex = st.text_input(
        "HTML regex",
        value="",
        placeholder=r'href="([^"]+communique[^"]*)"',
        help=(
            "Extract HTML page links by pattern.\n\n"
            "Examples:\n"
            r'`href="([^"]+)"'
            " — all href values\n\n"
            r'`href="([^"]*communique[^"]*)"'
            " — hrefs with 'communique'\n\n"
            r'`href="([^"]*investor[^"]*)"'
            " — hrefs with 'investor'\n\n"
            r'`<a[^>]+href="([^"]+)"[^>]*>`'
            " — full anchor tag hrefs\n\n"
            r'`<td[^>]*>\s*(https?://[^<]+)</td>`'
            " — URLs inside td tags\n\n"
            r'`data-url="([^"]+)"'
            " — data-url attributes"
        ),
        key="html_rx"
    )

# Parse
include_keywords = [
    kw.strip() for kw in include_input.split('|') if kw.strip()
]
exclude_keywords = [
    kw.strip() for kw in exclude_input.split('|') if kw.strip()
]

# Summary
parts = []
if include_keywords:
    parts.append(f"Keywords: `{include_keywords}`")
if pdf_regex.strip():
    parts.append(f"PDF regex active")
if html_regex.strip():
    parts.append(f"HTML regex active")
st.info(
    f"**Filters:** {' | '.join(parts) if parts else 'None set'}"
)

# ─────────────────────────────────────────────
# EXTRACT
# ─────────────────────────────────────────────
st.markdown("---")

if uploaded_file:
    try:
        har_content = uploaded_file.read().decode('utf-8')
    except UnicodeDecodeError:
        har_content = uploaded_file.read().decode(
            'utf-8', errors='ignore'
        )

    file_mb = len(har_content) / (1024 * 1024)
    st.caption(f"📁 {uploaded_file.name} | {file_mb:.1f} MB")

    if st.button("🚀 Extract URLs", type="primary", key="go"):

        with st.spinner("Parsing HAR file & unescaping bodies..."):
            bodies, parse_log = parse_har_bodies(har_content)
            st.session_state.body_texts = bodies
            st.session_state.extraction_log = parse_log

        all_results = []  # (url, matched_by, source_url)
        seen_urls = set()

        # ── Method 1: Keyword filtering ──
        if include_keywords:
            with st.spinner("Applying keyword filter..."):
                kw_results = apply_keyword_filter(
                    bodies, include_keywords, exclude_keywords
                )
                for url, matched, source in kw_results:
                    if url not in seen_urls:
                        seen_urls.add(url)
                        all_results.append(
                            (url, f"keyword: {matched}", source)
                        )
                st.session_state.keyword_matches = kw_results

        # ── Method 2: PDF regex ──
        if pdf_regex.strip():
            with st.spinner("Applying PDF regex..."):
                pdf_matches = apply_regex(bodies, pdf_regex.strip())
                regex_added = 0
                for raw, source, mime in pdf_matches:
                    cleaned = clean_url(raw)
                    if not cleaned:
                        # Might be a relative path — try as-is
                        if raw.startswith('/'):
                            cleaned = raw
                        else:
                            continue

                    if cleaned not in seen_urls:
                        # Check excludes
                        cl = cleaned.lower()
                        exc_lower = [
                            e.lower() for e in exclude_keywords
                        ]
                        if any(e in cl for e in exc_lower):
                            continue
                        seen_urls.add(cleaned)
                        all_results.append(
                            (cleaned, "pdf-regex", source)
                        )
                        regex_added += 1

                st.session_state.regex_matches = [
                    (clean_url(r) or r, s, m)
                    for r, s, m in pdf_matches
                ]

        # ── Method 3: HTML regex ──
        if html_regex.strip():
            with st.spinner("Applying HTML regex..."):
                html_matches = apply_regex(
                    bodies, html_regex.strip()
                )
                for raw, source, mime in html_matches:
                    cleaned = clean_url(raw)
                    if not cleaned:
                        if raw.startswith('/'):
                            # Try to build full URL from source
                            try:
                                from urllib.parse import urlparse
                                p = urlparse(source)
                                cleaned = f"{p.scheme}://{p.netloc}{raw}"
                            except Exception:
                                cleaned = raw
                        else:
                            continue

                    if cleaned not in seen_urls:
                        cl = cleaned.lower()
                        exc_lower = [
                            e.lower() for e in exclude_keywords
                        ]
                        if any(e in cl for e in exc_lower):
                            continue
                        seen_urls.add(cleaned)
                        all_results.append(
                            (cleaned, "html-regex", source)
                        )

        # Sort
        all_results.sort(
            key=lambda x: x[0].split('/')[-1].lower()
        )
        st.session_state.filtered_links = all_results
        st.session_state.har_loaded = True

        # Metrics
        m1, m2, m3 = st.columns(3)
        with m1:
            kw_count = len([
                r for r in all_results if 'keyword' in r[1]
            ])
            st.metric("🔑 Keyword Matches", kw_count)
        with m2:
            rx_count = len([
                r for r in all_results if 'regex' in r[1]
            ])
            st.metric("🔍 Regex Matches", rx_count)
        with m3:
            st.metric("📄 Total URLs", len(all_results))


# ─────────────────────────────────────────────
# RESULTS — ONLY MATCHED ITEMS
# ─────────────────────────────────────────────
if st.session_state.har_loaded and st.session_state.filtered_links:
    st.markdown("---")
    total = len(st.session_state.filtered_links)
    st.header(f"📄 {total} URLs Found")

    # Re-filter
    if st.button("🔄 Re-apply Filters", key="refilter"):
        # Re-run everything
        bodies = st.session_state.body_texts
        all_results = []
        seen_urls = set()

        if include_keywords:
            kw_results = apply_keyword_filter(
                bodies, include_keywords, exclude_keywords
            )
            for url, matched, source in kw_results:
                if url not in seen_urls:
                    seen_urls.add(url)
                    all_results.append(
                        (url, f"keyword: {matched}", source)
                    )

        if pdf_regex.strip():
            pdf_matches = apply_regex(bodies, pdf_regex.strip())
            for raw, source, mime in pdf_matches:
                cleaned = clean_url(raw) or raw
                if cleaned not in seen_urls:
                    cl = cleaned.lower()
                    exc_l = [e.lower() for e in exclude_keywords]
                    if not any(e in cl for e in exc_l):
                        seen_urls.add(cleaned)
                        all_results.append(
                            (cleaned, "pdf-regex", source)
                        )

        if html_regex.strip():
            html_matches = apply_regex(bodies, html_regex.strip())
            for raw, source, mime in html_matches:
                cleaned = clean_url(raw)
                if not cleaned and raw.startswith('/'):
                    try:
                        from urllib.parse import urlparse
                        p = urlparse(source)
                        cleaned = f"{p.scheme}://{p.netloc}{raw}"
                    except Exception:
                        cleaned = raw
                if cleaned and cleaned not in seen_urls:
                    cl = cleaned.lower()
                    exc_l = [e.lower() for e in exclude_keywords]
                    if not any(e in cl for e in exc_l):
                        seen_urls.add(cleaned)
                        all_results.append(
                            (cleaned, "html-regex", source)
                        )

        all_results.sort(
            key=lambda x: x[0].split('/')[-1].lower()
        )
        st.session_state.filtered_links = all_results
        st.rerun()

    # ── Display only matched results ──
    st.markdown("### Matched URLs Only:")

    for i, (url, matched_by, source) in enumerate(
        st.session_state.filtered_links, 1
    ):
        fname = url.split('/')[-1].split('?')[0]
        if len(fname) > 70:
            fname = fname[:67] + "..."
        if not fname:
            fname = url[:60]

        c1, c2, c3, c4 = st.columns([0.4, 3, 4.5, 2])
        with c1:
            st.text(f"{i}.")
        with c2:
            st.text(f"📄 {fname}")
        with c3:
            st.markdown(f"[Open Link]({url})")
        with c4:
            st.caption(matched_by)

    # ── Downloads ──
    st.markdown("---")
    st.header("⬇️ Download")

    d1, d2, d3 = st.columns(3)

    with d1:
        plain = "\n".join(
            u for u, _, _ in st.session_state.filtered_links
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
            pdf_regex, html_regex
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
        csv_lines = ["index,filename,url,matched_by,source"]
        for i, (url, mb, src) in enumerate(
            st.session_state.filtered_links, 1
        ):
            fn = url.split('/')[-1].split('?')[0].replace(',', '_')
            csv_lines.append(
                f'{i},"{fn}","{url}","{mb}","{src[:80]}"'
            )
        st.download_button(
            "📊 CSV (.csv)",
            data="\n".join(csv_lines),
            file_name=(
                f"urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            ),
            mime="text/csv"
        )

    # Copy box
    st.markdown("---")
    st.subheader("📋 Copy-Paste")
    st.text_area(
        "All URLs",
        value="\n".join(
            u for u, _, _ in st.session_state.filtered_links
        ),
        height=200,
        key="copy"
    )


# ─────────────────────────────────────────────
# DEBUG — only matched, with body search
# ─────────────────────────────────────────────
if st.session_state.har_loaded:
    st.markdown("---")
    st.subheader("🔧 Debug Tools")

    # Body search — helps find the right regex
    if st.session_state.body_texts:
        with st.expander("🔍 Search Response Bodies"):
            st.caption(
                "Search inside actual response content "
                "to build the right regex."
            )

            body_search = st.text_input(
                "Search term",
                placeholder=(
                    "communique, .pdf, investor, report..."
                ),
                key="body_search"
            )

            if body_search:
                match_count = 0
                for mime, req_url, body in st.session_state.body_texts:
                    if body_search.lower() in body.lower():
                        match_count += 1

                        st.markdown(f"**{match_count}. {mime}**")
                        st.caption(f"From: {req_url[:100]}")

                        # Show context around the match
                        idx = body.lower().find(
                            body_search.lower()
                        )
                        if idx >= 0:
                            start = max(0, idx - 300)
                            end = min(len(body), idx + 500)
                            snippet = body[start:end]

                            # Highlight the match
                            st.code(snippet, language="html")
                        else:
                            st.code(body[:500], language="html")

                        st.markdown("---")

                        if match_count >= 15:
                            st.caption(
                                "Showing first 15 matches..."
                            )
                            break

                if match_count == 0:
                    st.warning(
                        f"'{body_search}' not found in any "
                        f"response body"
                    )
                else:
                    st.success(
                        f"Found in {match_count} response(s). "
                        f"Use the context above to build your regex."
                    )

    # Extraction log
    if st.session_state.extraction_log:
        with st.expander("📋 Extraction Log"):
            for entry in st.session_state.extraction_log:
                st.text(entry)


# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.header("📖 Guide")

    st.markdown("### Keywords (Simple)")
    st.code(".pdf", language="text")
    st.caption("URLs containing .pdf")
    st.code(".pdf|.xlsx|.docx", language="text")
    st.caption("Multiple file types")
    st.code("communique-de-presse", language="text")
    st.caption("HTML pages with this path")

    st.markdown("### PDF Regex")
    st.code(
        r'https?://[^\s"<>]+\.pdf[^\s"<>]*',
        language="text"
    )
    st.caption("Any PDF URL anywhere")

    st.code(
        r'"url"\s*:\s*"([^"]+\.pdf)',
        language="text"
    )
    st.caption("PDF URL in JSON key 'url'")

    st.markdown("### HTML Regex")
    st.code(
        r'href="([^"]+)"',
        language="text"
    )
    st.caption("All href values")

    st.code(
        r'href="([^"]*communique[^"]*)"',
        language="text"
    )
    st.caption("hrefs containing 'communique'")

    st.code(
        r'<a[^>]+href="([^"]+)"',
        language="text"
    )
    st.caption("Anchor tag hrefs")

    st.code(
        r'<td[^>]*>\s*(https?://[^<]+)</td>',
        language="text"
    )
    st.caption("URLs inside td tags")

    st.code(
        r'data-url="([^"]+)"',
        language="text"
    )
    st.caption("data-url attributes")

    st.markdown("---")
    st.markdown("### Debugging")
    st.markdown("""
    1. Use **Search Response Bodies**
    2. Type what you're looking for
    3. See the actual content
    4. Build regex from context
    5. Click **Re-apply Filters**
    """)

    st.markdown("---")
    if st.button("🗑️ Clear"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()
