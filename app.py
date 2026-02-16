import streamlit as st
import json
import re
from datetime import datetime
from urllib.parse import unquote, urljoin, urlparse
from bs4 import BeautifulSoup

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
    'body_texts': [],
    'har_loaded': False,
    'extraction_log': [],
}
for key, val in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val if not isinstance(val, list) else []


# ─────────────────────────────────────────────
# Unescape JSON string
# ─────────────────────────────────────────────
def unescape_json_string(text):
    """
    HAR stores response bodies as JSON string values.
    HTML like <a href="url"> becomes <a href=\\\"url\\\">
    This reverses ALL escaping.
    """
    if not text or not isinstance(text, str):
        return ""

    s = text

    # Unicode escapes
    s = s.replace('\\u003c', '<')
    s = s.replace('\\u003e', '>')
    s = s.replace('\\u0026', '&')
    s = s.replace('\\u003d', '=')
    s = s.replace('\\u0022', '"')
    s = s.replace('\\u0027', "'")

    # JSON string escapes (multiple passes)
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

    s = re.sub(r'\\+/', '/', s)

    # Remove wrapping quotes
    s = s.strip()
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]

    return s


# ─────────────────────────────────────────────
# Clean URL
# ─────────────────────────────────────────────
def clean_url(url):
    if not url or not isinstance(url, str):
        return ""

    cleaned = url.strip().strip('"\'')

    for _ in range(5):
        old = cleaned
        cleaned = cleaned.replace('\\/', '/')
        cleaned = cleaned.replace('\\\\/', '/')
        cleaned = cleaned.replace('\\"', '')
        cleaned = cleaned.replace('\\n', '')
        cleaned = cleaned.replace('\\r', '')
        cleaned = cleaned.replace('\\u0026', '&')
        if cleaned == old:
            break

    cleaned = re.sub(r'\\+/', '/', cleaned)

    if '%2F' in cleaned or '%3A' in cleaned:
        try:
            cleaned = unquote(cleaned)
        except Exception:
            pass

    if cleaned.startswith('//'):
        cleaned = 'https:' + cleaned
    elif not cleaned.startswith('http'):
        return ""

    cleaned = cleaned.replace('\\', '/')
    cleaned = re.sub(r'(?<!:)/{2,}', '/', cleaned)
    cleaned = cleaned.rstrip('\\",;\')} \t\n\r>')

    if '#' in cleaned:
        cleaned = cleaned.split('#')[0]

    if not re.match(r'https?://.+\..+', cleaned):
        return ""

    return cleaned


# ─────────────────────────────────────────────
# Extract URLs from HTML
# ─────────────────────────────────────────────
def extract_urls_from_html(html_string, base_url=""):
    urls = set()
    if not html_string or len(html_string) < 10:
        return urls

    try:
        soup = BeautifulSoup(html_string, 'html.parser')
    except Exception:
        return urls

    url_attrs = [
        'href', 'src', 'data-href', 'data-src',
        'data-url', 'data-file', 'data-download',
        'data-pdf', 'data-link', 'data-path',
        'action', 'content', 'value',
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

    for tag in soup.find_all(True):
        if tag.string:
            found = re.findall(
                r'https?://[^\s<>"\']+', tag.string
            )
            urls.update(found)

    for attr in ['onclick', 'onmousedown']:
        for tag in soup.find_all(attrs={attr: True}):
            val = tag.get(attr, '')
            found = re.findall(
                r'["\']?(https?://[^\s"\'<>)]+)', val
            )
            urls.update(found)

    return urls


# ─────────────────────────────────────────────
# Parse HAR → collect unescaped bodies
# ─────────────────────────────────────────────
def parse_har_bodies(har_content):
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

        # Unescape body
        unescaped = unescape_json_string(body)
        bodies.append((mime, req_url, unescaped))

        # For JSON bodies, extract HTML fragments from values
        if ('json' in mime
                or unescaped.strip().startswith(('{', '['))):
            try:
                data = json.loads(unescaped)
                html_frags = extract_html_from_json(data)
                for frag in html_frags:
                    clean_frag = unescape_json_string(frag)
                    if '<' in clean_frag and '>' in clean_frag:
                        bodies.append((
                            'text/html (from json)',
                            req_url,
                            clean_frag
                        ))
            except json.JSONDecodeError:
                pass

    log.append(f"Collected {len(bodies)} response bodies")
    return bodies, log


def extract_html_from_json(data):
    html_strings = []

    def recurse(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                if isinstance(v, str):
                    check(v)
                else:
                    recurse(v)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, str):
                    check(item)
                else:
                    recurse(item)

    def check(value):
        if not value or len(value) < 20:
            return
        indicators = [
            '<a ', '<a\n', '<div', '<span', '<td',
            '<tr', '<table', '<p ', '<p>', '<li',
            '<ul', '<article', '<section',
            'href=', 'src=',
        ]
        vl = value.lower()
        if any(ind in vl for ind in indicators):
            html_strings.append(value)

    recurse(data)
    return html_strings


# ─────────────────────────────────────────────
# SMART REGEX: Find URLs AROUND a match
# ─────────────────────────────────────────────
def find_urls_around_match(body, match_text, match_start):
    """
    When a regex matches something that is NOT a URL
    (like 'communique-de-presse'), search the surrounding
    context to find the actual URL containing that text.
    
    Strategy:
    1. Look backwards and forwards from match position
    2. Find the enclosing href="..." or src="..."
    3. Or find the full URL that contains the match text
    """
    urls = set()

    # Search window: 500 chars before and after
    window_start = max(0, match_start - 500)
    window_end = min(len(body), match_start + len(match_text) + 500)
    context = body[window_start:window_end]

    # Strategy 1: Find href/src containing the match
    href_patterns = [
        r'href\s*=\s*["\']([^"\']*' + re.escape(match_text) + r'[^"\']*)["\']',
        r'src\s*=\s*["\']([^"\']*' + re.escape(match_text) + r'[^"\']*)["\']',
        r'data-url\s*=\s*["\']([^"\']*' + re.escape(match_text) + r'[^"\']*)["\']',
        r'data-href\s*=\s*["\']([^"\']*' + re.escape(match_text) + r'[^"\']*)["\']',
        r'action\s*=\s*["\']([^"\']*' + re.escape(match_text) + r'[^"\']*)["\']',
    ]

    for pattern in href_patterns:
        try:
            found = re.findall(pattern, context, re.IGNORECASE)
            urls.update(found)
        except re.error:
            pass

    # Strategy 2: Find full URL containing the match text
    url_pattern = (
        r'(https?://[^\s"\'<>]*'
        + re.escape(match_text)
        + r'[^\s"\'<>]*)'
    )
    try:
        found = re.findall(url_pattern, context, re.IGNORECASE)
        urls.update(found)
    except re.error:
        pass

    # Strategy 3: Find JSON value containing the match
    json_patterns = [
        r'"(?:url|href|link|path|file|src)"\s*:\s*"([^"]*'
        + re.escape(match_text) + r'[^"]*)"',
    ]
    for pattern in json_patterns:
        try:
            found = re.findall(pattern, context, re.IGNORECASE)
            urls.update(found)
        except re.error:
            pass

    return urls


# ─────────────────────────────────────────────
# SMART REGEX APPLICATION
# ─────────────────────────────────────────────
def apply_smart_regex(bodies, pattern, exclude_keywords):
    """
    Apply regex on response bodies with SMART URL extraction.
    
    If regex returns a full URL → use it directly.
    If regex returns a non-URL text → search around
    the match to find the enclosing URL.
    
    This means BOTH of these work:
    
    1. href="([^"]*communique[^"]*)"   → returns URL directly
    2. communique-de-presse             → finds URL around match
    """
    results = []
    seen = set()

    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        st.error(f"Invalid regex pattern: `{pattern}`\nError: {e}")
        return results

    exc_lower = [e.strip().lower() for e in exclude_keywords if e.strip()]

    # Auto excludes
    auto_exc = [
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp',
        '.ico', '.css', '.woff', '.woff2', '.ttf',
        '.mp4', '.mp3', '.webm',
        'google-analytics', 'googletagmanager',
        'doubleclick.net',
    ]
    all_exc = exc_lower + auto_exc

    for mime, req_url, body in bodies:
        if not body:
            continue

        # Get base URL from request
        try:
            p = urlparse(req_url)
            base_url = f"{p.scheme}://{p.netloc}"
        except Exception:
            base_url = ""

        # Find all matches with positions
        for match_obj in compiled.finditer(body):

            # Get the matched text
            # If there are groups, use group(1), else group(0)
            if match_obj.lastindex and match_obj.lastindex >= 1:
                matched_text = match_obj.group(1)
            else:
                matched_text = match_obj.group(0)

            if not matched_text or len(matched_text) < 3:
                continue

            match_start = match_obj.start()

            # ── Check if match IS already a URL ──
            cleaned = clean_url(matched_text)

            if cleaned:
                # It's a valid URL
                if cleaned not in seen:
                    if not any(e in cleaned.lower() for e in all_exc):
                        seen.add(cleaned)
                        results.append((
                            cleaned, f"regex-direct", req_url
                        ))
                continue

            # ── Match is NOT a URL — find URL around it ──
            surrounding_urls = find_urls_around_match(
                body, matched_text, match_start
            )

            for raw_url in surrounding_urls:
                cleaned = clean_url(raw_url)
                if not cleaned:
                    # Try as relative URL
                    if raw_url.startswith('/') and base_url:
                        cleaned = base_url + raw_url
                    else:
                        continue

                if cleaned not in seen:
                    if not any(e in cleaned.lower() for e in all_exc):
                        seen.add(cleaned)
                        results.append((
                            cleaned, f"regex-context", req_url
                        ))

    results.sort(key=lambda x: x[0].split('/')[-1].lower())
    return results


# ─────────────────────────────────────────────
# Keyword filter on bodies
# ─────────────────────────────────────────────
def apply_keyword_filter(bodies, include_keywords, exclude_keywords):
    results = []
    seen = set()

    inc = [kw.strip().lower() for kw in include_keywords if kw.strip()]
    exc = [kw.strip().lower() for kw in exclude_keywords if kw.strip()]

    auto_exc = [
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp',
        '.ico', '.css', '.woff', '.woff2', '.ttf',
        '.mp4', '.mp3', '.webm',
        'google-analytics', 'googletagmanager',
        'doubleclick.net',
    ]
    all_exc = exc + auto_exc

    for mime, req_url, body in bodies:
        if not body:
            continue

        try:
            p = urlparse(req_url)
            base = f"{p.scheme}://{p.netloc}" if p.scheme else ""
        except Exception:
            base = ""

        found_urls = set()

        # Parse HTML
        if '<' in body and '>' in body:
            found_urls.update(extract_urls_from_html(body, base))

        # Raw URL regex
        raw = re.findall(r'https?://[^\s"\'<>\\,;\]})]+', body)
        found_urls.update(raw)

        # Filter
        for raw_url in found_urls:
            cleaned = clean_url(raw_url)
            if not cleaned or cleaned in seen:
                continue

            cl = cleaned.lower()
            if any(e in cl for e in all_exc):
                continue

            matched = None
            for kw in inc:
                if kw in cl:
                    matched = kw
                    break

            if matched:
                seen.add(cleaned)
                results.append((cleaned, f"keyword: {matched}", req_url))

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
    ]
    if inc_kw:
        lines.append(f"Keywords     : {', '.join(inc_kw)}")
    if pdf_regex:
        lines.append(f"PDF Regex    : {pdf_regex}")
    if html_regex:
        lines.append(f"HTML Regex   : {html_regex}")
    lines.append(f"Excludes     : {len(exc_kw)} patterns")

    lines.extend(["=" * 70, "", "── EXTRACTED URLS ──", ""])

    for i, (url, matched_by, src) in enumerate(results, 1):
        fname = url.split('/')[-1].split('?')[0]
        lines.append(f"{i:4d}. {fname}")
        lines.append(f"      {url}")
        lines.append(f"      [matched: {matched_by}]")
        lines.append("")

    lines.extend(["=" * 70, "", "── PLAIN URL LIST ──", ""])
    for url, _, _ in results:
        lines.append(url)

    lines.extend(["", "=" * 70, "END"])
    return "\n".join(lines)


# ═════════════════════════════════════════════
# UI
# ═════════════════════════════════════════════

st.title("📄 HAR → URL Extractor")
st.markdown(
    "Upload `.har` file → Extract PDF, HTML, or any URLs "
    "using **keywords + smart regex**"
)

with st.expander("📖 How to capture .har file"):
    st.markdown("""
    1. Chrome → target website → F12 → Network tab
    2. Check **"Preserve log"**
    3. **Click ALL tabs/buttons** on the page
    4. Right-click in Network list → **Save all as HAR with content**
    5. Upload here
    """)

st.markdown("---")

# Upload
uploaded_file = st.file_uploader("📁 Upload .har file", type=['har'])

# ─── Filter Settings ───
st.markdown("---")
st.subheader("🔧 Extraction Settings")
st.markdown(
    "Use **Keywords** for simple matching, "
    "**Regex** for advanced patterns. "
    "Results from ALL methods are combined."
)

kw1, kw2 = st.columns(2)
with kw1:
    st.markdown("**✅ Include Keywords** (URL must contain ≥1)")
    include_input = st.text_input(
        "Keywords (separate with |)",
        value=".pdf",
        placeholder=".pdf|/download/|.xlsx",
        key="inc"
    )
with kw2:
    st.markdown("**❌ Exclude Keywords**")
    exclude_input = st.text_input(
        "Exclude (separate with |)",
        value=(
            ".jpg|.jpeg|.png|.gif|.svg|.webp|.ico|"
            ".css|.woff|.woff2"
        ),
        key="exc"
    )

st.markdown("---")
st.subheader("🔍 Regex Patterns (Smart)")
st.markdown("""
**How smart regex works:**
- If your regex **captures a full URL** → used directly  
- If your regex **matches text that's NOT a URL** (like `communique-de-presse`) 
  → the app automatically searches the surrounding HTML/JSON to find 
  the **full URL containing that text**

**So both of these work:**
- `communique-de-presse` — finds URLs containing this text
- `href="([^"]*communique[^"]*)"` — extracts URL from href directly
""")

rx1, rx2 = st.columns(2)
with rx1:
    st.markdown("**📄 PDF / Document Regex**")
    pdf_regex = st.text_input(
        "PDF regex",
        value="",
        placeholder=r'\.pdf',
        help=(
            "Simple examples:\n"
            "  `.pdf` — any body text containing .pdf\n"
            "  `annual-report` — finds URLs with this text\n\n"
            "Advanced examples:\n"
            "  `https?://[^\\s\"<>]+\\.pdf` — full PDF URLs\n"
            "  `href=\"([^\"]+\\.pdf[^\"]*)\"` — PDF in href"
        ),
        key="pdf_rx"
    )
with rx2:
    st.markdown("**🌐 HTML / Page Link Regex**")
    html_regex = st.text_input(
        "HTML regex",
        value="",
        placeholder="communique-de-presse",
        help=(
            "Simple examples:\n"
            "  `communique-de-presse` — URLs with this path\n"
            "  `investor` — any URL containing 'investor'\n"
            "  `/en/press/` — specific path pattern\n\n"
            "Advanced examples:\n"
            "  `href=\"([^\"]*communique[^\"]*)\"` — from href\n"
            "  `<a[^>]+href=\"([^\"]+)\"` — all anchor hrefs\n"
            "  `<td[^>]*>\\s*(https?://[^<]+)</td>` — URLs in td"
        ),
        key="html_rx"
    )

include_keywords = [
    kw.strip() for kw in include_input.split('|') if kw.strip()
]
exclude_keywords = [
    kw.strip() for kw in exclude_input.split('|') if kw.strip()
]

# Summary
parts = []
if include_keywords:
    parts.append(f"Keywords: `{'`, `'.join(include_keywords)}`")
if pdf_regex.strip():
    parts.append(f"PDF regex: `{pdf_regex.strip()}`")
if html_regex.strip():
    parts.append(f"HTML regex: `{html_regex.strip()}`")
st.info(
    f"**Active:** {' | '.join(parts)}" if parts else
    "**⚠️ No filters set — add keywords or regex above**"
)

# ─── Extract ───
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

        with st.spinner("Parsing HAR & unescaping bodies..."):
            bodies, parse_log = parse_har_bodies(har_content)
            st.session_state.body_texts = bodies
            st.session_state.extraction_log = parse_log

        all_results = []
        seen = set()

        # Method 1: Keywords
        if include_keywords:
            with st.spinner(
                f"Keyword search: {include_keywords}..."
            ):
                kw_res = apply_keyword_filter(
                    bodies, include_keywords, exclude_keywords
                )
                for url, mb, src in kw_res:
                    if url not in seen:
                        seen.add(url)
                        all_results.append((url, mb, src))

        # Method 2: PDF regex
        if pdf_regex.strip():
            with st.spinner(f"PDF regex: {pdf_regex.strip()}..."):
                pdf_res = apply_smart_regex(
                    bodies, pdf_regex.strip(), exclude_keywords
                )
                for url, mb, src in pdf_res:
                    if url not in seen:
                        seen.add(url)
                        all_results.append((url, f"pdf-{mb}", src))

        # Method 3: HTML regex
        if html_regex.strip():
            with st.spinner(f"HTML regex: {html_regex.strip()}..."):
                html_res = apply_smart_regex(
                    bodies, html_regex.strip(), exclude_keywords
                )
                for url, mb, src in html_res:
                    if url not in seen:
                        seen.add(url)
                        all_results.append(
                            (url, f"html-{mb}", src)
                        )

        all_results.sort(
            key=lambda x: x[0].split('/')[-1].lower()
        )
        st.session_state.filtered_links = all_results
        st.session_state.har_loaded = True

        # Metrics
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            c = len([r for r in all_results if 'keyword' in r[1]])
            st.metric("🔑 Keyword", c)
        with m2:
            c = len([r for r in all_results if 'pdf' in r[1]])
            st.metric("📄 PDF Regex", c)
        with m3:
            c = len([r for r in all_results if 'html' in r[1]])
            st.metric("🌐 HTML Regex", c)
        with m4:
            st.metric("📊 Total", len(all_results))

# ─── Results ───
if st.session_state.har_loaded and st.session_state.filtered_links:
    st.markdown("---")
    total = len(st.session_state.filtered_links)
    st.header(f"📄 {total} URLs Found")

    if st.button("🔄 Re-apply Filters", key="refilter"):
        bodies = st.session_state.body_texts
        all_results = []
        seen = set()

        if include_keywords:
            for url, mb, src in apply_keyword_filter(
                bodies, include_keywords, exclude_keywords
            ):
                if url not in seen:
                    seen.add(url)
                    all_results.append((url, mb, src))

        if pdf_regex.strip():
            for url, mb, src in apply_smart_regex(
                bodies, pdf_regex.strip(), exclude_keywords
            ):
                if url not in seen:
                    seen.add(url)
                    all_results.append((url, f"pdf-{mb}", src))

        if html_regex.strip():
            for url, mb, src in apply_smart_regex(
                bodies, html_regex.strip(), exclude_keywords
            ):
                if url not in seen:
                    seen.add(url)
                    all_results.append((url, f"html-{mb}", src))

        all_results.sort(
            key=lambda x: x[0].split('/')[-1].lower()
        )
        st.session_state.filtered_links = all_results
        st.rerun()

    # Display
    for i, (url, matched_by, source) in enumerate(
        st.session_state.filtered_links, 1
    ):
        fname = url.split('/')[-1].split('?')[0]
        if len(fname) > 60:
            fname = fname[:57] + "..."
        if not fname:
            fname = url[:50]

        c1, c2, c3, c4 = st.columns([0.4, 2.8, 4.5, 2])
        with c1:
            st.text(f"{i}.")
        with c2:
            st.text(f"📄 {fname}")
        with c3:
            st.markdown(f"[Open Link]({url})")
        with c4:
            st.caption(matched_by)

    # Downloads
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
            file_name=f"urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
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
            "📋 Report (.txt)",
            data=report,
            file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )
    with d3:
        csv = ["index,filename,url,matched_by"]
        for i, (u, m, _) in enumerate(
            st.session_state.filtered_links, 1
        ):
            fn = u.split('/')[-1].split('?')[0].replace(',', '_')
            csv.append(f'{i},"{fn}","{u}","{m}"')
        st.download_button(
            "📊 CSV (.csv)",
            data="\n".join(csv),
            file_name=f"urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

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

# ─── Debug ───
if st.session_state.har_loaded:
    st.markdown("---")
    st.subheader("🔧 Debug: Search Response Bodies")
    st.caption(
        "Search inside response content to find "
        "the right keyword or regex pattern."
    )

    if st.session_state.body_texts:
        body_search = st.text_input(
            "🔍 Search",
            placeholder="communique, .pdf, investor...",
            key="bsearch"
        )

        if body_search:
            count = 0
            for mime, req_url, body in st.session_state.body_texts:
                if body_search.lower() in body.lower():
                    count += 1
                    with st.expander(
                        f"{count}. [{mime[:30]}] {req_url[:80]}"
                    ):
                        idx = body.lower().find(
                            body_search.lower()
                        )
                        start = max(0, idx - 300)
                        end = min(len(body), idx + 500)
                        snippet = body[start:end]
                        st.code(snippet, language="html")

                    if count >= 15:
                        st.caption("Showing first 15...")
                        break

            if count:
                st.success(f"Found in {count} response(s)")
            else:
                st.warning(f"'{body_search}' not found")

    if st.session_state.extraction_log:
        with st.expander("📋 Parse Log"):
            for e in st.session_state.extraction_log:
                st.text(e)

# ─── Sidebar ───
with st.sidebar:
    st.header("📖 Quick Reference")

    st.markdown("### Simple (just type text)")
    st.code("communique-de-presse", language="text")
    st.caption("→ Finds all URLs containing this text")

    st.code(".pdf", language="text")
    st.caption("→ Finds all PDF URLs")

    st.code("annual-report", language="text")
    st.caption("→ Finds URLs with 'annual-report'")

    st.markdown("### Advanced Regex")
    st.code(r'href="([^"]*investor[^"]*)"', language="text")
    st.caption("→ href values containing 'investor'")

    st.code(r'https?://[^\s"]+\.pdf', language="text")
    st.caption("→ Full PDF URLs from any text")

    st.code(r'<td[^>]*>\s*(https?://[^<]+)</td>', language="text")
    st.caption("→ URLs inside td tags")

    st.markdown("---")
    st.markdown("""
    ### How Smart Regex Works
    
    ```
    You type: communique-de-presse
    
    App finds this in body text.
    
    Then searches AROUND the match:
    → Found href="https://...communique-de-presse/..."
    → Extracts the full URL
    → Returns clean working link
    ```
    """)

    st.markdown("---")
    if st.button("🗑️ Clear"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()
