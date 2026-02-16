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
# Date patterns
# ─────────────────────────────────────────────
DATE_PATTERNS = [
    # 15 Jan 2025, 15 January 2025
    r'\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}',
    # Jan 15, 2025 / January 15, 2025
    r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}',
    # 2025-01-15
    r'\d{4}-\d{2}-\d{2}',
    # 15/01/2025 or 01/15/2025
    r'\d{1,2}/\d{1,2}/\d{4}',
    # 15-01-2025 or 01-15-2025
    r'\d{1,2}-\d{1,2}-\d{4}',
    # 15.01.2025
    r'\d{1,2}\.\d{1,2}\.\d{4}',
    # March 2025
    r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}',
    # Q1 2025, Q2 FY2025
    r'Q[1-4]\s*(?:FY)?\s*\d{4}',
    # FY 2024-25
    r'FY\s*\d{4}(?:-\d{2,4})?',
    # 2024-25
    r'\d{4}-\d{2,4}',
]

DATE_REGEX = re.compile(
    '(' + '|'.join(DATE_PATTERNS) + ')',
    re.IGNORECASE
)


# ─────────────────────────────────────────────
# Unescape JSON string
# ─────────────────────────────────────────────
def unescape_json_string(text):
    if not text or not isinstance(text, str):
        return ""

    s = text
    s = s.replace('\\u003c', '<')
    s = s.replace('\\u003e', '>')
    s = s.replace('\\u0026', '&')
    s = s.replace('\\u003d', '=')
    s = s.replace('\\u0022', '"')
    s = s.replace('\\u0027', "'")

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
# Extract title and date from context around URL
# ─────────────────────────────────────────────
def extract_metadata_from_context(body, url, match_start):
    """
    Given a URL found at position match_start in body,
    search the surrounding HTML to find:
    - Title: link text, nearby heading, title attribute
    - Date: nearby date string

    Returns: (title, date)
    """
    title = ""
    date = ""

    # Get a window of text around the match
    window_start = max(0, match_start - 1000)
    window_end = min(len(body), match_start + len(url) + 1000)
    context = body[window_start:window_end]

    escaped_url = re.escape(url)
    # Also try partial match (last part of URL)
    url_tail = url.split('/')[-1] if '/' in url else url
    escaped_tail = re.escape(url_tail)

    # ── TITLE EXTRACTION ──

    # Method 1: <a href="URL">TITLE</a>
    patterns_title = [
        # Full URL in href
        r'<a[^>]*href\s*=\s*["\'][^"\']*'
        + escaped_tail
        + r'[^"\']*["\'][^>]*>\s*(.*?)\s*</a>',
        # Any anchor with this URL, get text
        r'href\s*=\s*["\'][^"\']*'
        + escaped_tail
        + r'[^"\']*["\'][^>]*>\s*([^<]+)',
    ]

    for pattern in patterns_title:
        try:
            match = re.search(pattern, context, re.IGNORECASE | re.DOTALL)
            if match:
                raw_title = match.group(1).strip()
                # Clean HTML from title
                raw_title = re.sub(r'<[^>]+>', ' ', raw_title)
                raw_title = re.sub(r'\s+', ' ', raw_title).strip()
                if raw_title and len(raw_title) > 2:
                    title = raw_title
                    break
        except re.error:
            pass

    # Method 2: title="..." attribute on the link
    if not title:
        try:
            pattern = (
                r'<a[^>]*href\s*=\s*["\'][^"\']*'
                + escaped_tail
                + r'[^"\']*["\'][^>]*title\s*=\s*["\']([^"\']+)["\']'
            )
            match = re.search(pattern, context, re.IGNORECASE)
            if match:
                title = match.group(1).strip()
        except re.error:
            pass

    # Method 3: Nearby heading or strong text
    if not title:
        try:
            # Look for headings near the URL
            pattern = (
                r'<(?:h[1-6]|strong|b)[^>]*>\s*([^<]+?)\s*'
                r'</(?:h[1-6]|strong|b)>'
            )
            matches = re.findall(pattern, context, re.IGNORECASE)
            for m in matches:
                m = m.strip()
                if m and len(m) > 3 and len(m) < 200:
                    title = m
                    break
        except re.error:
            pass

    # Method 4: Nearby div/span with title-like class
    if not title:
        try:
            pattern = (
                r'<(?:div|span)[^>]*class\s*=\s*["\'][^"\']*'
                r'(?:title|name|heading|label)[^"\']*["\'][^>]*>'
                r'\s*([^<]+?)\s*</(?:div|span)>'
            )
            matches = re.findall(pattern, context, re.IGNORECASE)
            for m in matches:
                m = m.strip()
                if m and len(m) > 3 and len(m) < 200:
                    title = m
                    break
        except re.error:
            pass

    # Method 5: Use BeautifulSoup on context
    if not title:
        try:
            soup = BeautifulSoup(context, 'html.parser')

            # Find the <a> tag with our URL
            for a_tag in soup.find_all('a', href=True):
                href = a_tag.get('href', '')
                if url_tail in href or url in href:
                    # Get link text
                    link_text = a_tag.get_text(strip=True)
                    if link_text and len(link_text) > 2:
                        title = link_text
                        break

                    # Check title attribute
                    t = a_tag.get('title', '').strip()
                    if t:
                        title = t
                        break

            # If still no title, check parent elements
            if not title:
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag.get('href', '')
                    if url_tail in href or url in href:
                        parent = a_tag.parent
                        while parent and parent.name:
                            # Check siblings for title text
                            for sibling in parent.children:
                                if sibling == a_tag:
                                    continue
                                if hasattr(sibling, 'get_text'):
                                    sib_text = sibling.get_text(strip=True)
                                    if (sib_text
                                            and len(sib_text) > 3
                                            and len(sib_text) < 200
                                            and not sib_text.startswith('http')):
                                        title = sib_text
                                        break
                            if title:
                                break
                            parent = parent.parent
                            # Don't go too far up
                            if parent and parent.name in [
                                'body', 'html', 'main', 'section'
                            ]:
                                break
        except Exception:
            pass

    # ── DATE EXTRACTION ──

    # Method 1: Date from nearby HTML
    date_matches = DATE_REGEX.findall(context)
    if date_matches:
        # Pick the closest date to the URL position
        # (dates found in the context window)
        date = date_matches[0].strip()

    # Method 2: Date from specific HTML elements
    if not date:
        try:
            date_patterns_html = [
                r'<(?:time|span|div)[^>]*(?:class|datetime)\s*=\s*["\'][^"\']*'
                r'(?:date|time|published|posted)[^"\']*["\'][^>]*>\s*([^<]+)',
                r'<time[^>]*datetime\s*=\s*["\']([^"\']+)["\']',
                r'<(?:span|div)[^>]*class\s*=\s*["\'][^"\']*date[^"\']*["\'][^>]*>\s*([^<]+)',
            ]
            for pattern in date_patterns_html:
                match = re.search(pattern, context, re.IGNORECASE)
                if match:
                    d = match.group(1).strip()
                    if d and len(d) < 50:
                        date = d
                        break
        except re.error:
            pass

    # Method 3: Date from BeautifulSoup
    if not date:
        try:
            soup = BeautifulSoup(context, 'html.parser')

            # <time> tags
            for time_tag in soup.find_all('time'):
                dt = time_tag.get('datetime', '')
                if dt:
                    date = dt.strip()
                    break
                t = time_tag.get_text(strip=True)
                if t:
                    date = t
                    break

            # Elements with date-related classes
            if not date:
                for tag in soup.find_all(
                    class_=re.compile(
                        r'date|time|publish|posted|created',
                        re.IGNORECASE
                    )
                ):
                    t = tag.get_text(strip=True)
                    if t and len(t) < 50:
                        # Verify it looks like a date
                        if DATE_REGEX.search(t):
                            date = t
                            break
        except Exception:
            pass

    # Method 4: Date from JSON context
    if not date:
        json_date_patterns = [
            r'"(?:date|published|created|updated|timestamp|'
            r'publishDate|createdAt|updatedAt|postDate|'
            r'release_date|publish_date|filing_date)"\s*:\s*'
            r'"([^"]+)"',
        ]
        for pattern in json_date_patterns:
            try:
                match = re.search(pattern, context, re.IGNORECASE)
                if match:
                    date = match.group(1).strip()
                    break
            except re.error:
                pass

    # Method 5: Date from URL itself
    if not date:
        # URLs like /2025/01/ or /2025-01/
        url_date = re.search(
            r'/(\d{4})[/-](\d{2})(?:[/-](\d{2}))?/',
            url
        )
        if url_date:
            y, m = url_date.group(1), url_date.group(2)
            d_part = url_date.group(3)
            if d_part:
                date = f"{y}-{m}-{d_part}"
            else:
                date = f"{y}-{m}"

    # Method 6: Date from filename
    if not date:
        fname = url.split('/')[-1]
        # Patterns like Report-March2024.pdf
        fname_date = re.search(
            r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'
            r'[a-z]*[-_]?\d{4}',
            fname, re.IGNORECASE
        )
        if fname_date:
            date = fname_date.group(0)

        if not date:
            # Patterns like 20240315 or 2024-03-15 in filename
            fname_date2 = re.search(
                r'(\d{4})[-_]?(\d{2})[-_]?(\d{2})',
                fname
            )
            if fname_date2:
                y = fname_date2.group(1)
                m = fname_date2.group(2)
                d_val = fname_date2.group(3)
                if 2000 <= int(y) <= 2030:
                    date = f"{y}-{m}-{d_val}"

    # Clean up title
    if title:
        title = re.sub(r'<[^>]+>', '', title)
        title = re.sub(r'\s+', ' ', title).strip()
        title = title.strip('|/-:. ')
        if len(title) > 150:
            title = title[:147] + "..."

    # Clean up date
    if date:
        date = date.strip('|/-:,. ')
        # Remove time portion if present
        date = re.sub(r'T\d{2}:\d{2}.*$', '', date)
        date = date.strip()

    return title, date


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
        'data-pdf', 'data-link', 'action', 'content',
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
# Parse HAR bodies
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
        unescaped = unescape_json_string(body)
        bodies.append((mime, req_url, unescaped))

        if ('json' in mime
                or unescaped.strip().startswith(('{', '['))):
            try:
                data = json.loads(unescaped)
                for frag in extract_html_from_json(data):
                    clean_frag = unescape_json_string(frag)
                    if '<' in clean_frag and '>' in clean_frag:
                        bodies.append((
                            'text/html (from json)',
                            req_url, clean_frag
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
            'href=', 'src=',
        ]
        vl = value.lower()
        if any(ind in vl for ind in indicators):
            html_strings.append(value)

    recurse(data)
    return html_strings


# ─────────────────────────────────────────────
# Find URLs around a non-URL regex match
# ─────────────────────────────────────────────
def find_urls_around_match(body, match_text, match_start):
    urls = set()
    window_start = max(0, match_start - 500)
    window_end = min(len(body), match_start + len(match_text) + 500)
    context = body[window_start:window_end]

    escaped = re.escape(match_text)

    href_patterns = [
        r'href\s*=\s*["\']([^"\']*' + escaped + r'[^"\']*)["\']',
        r'src\s*=\s*["\']([^"\']*' + escaped + r'[^"\']*)["\']',
        r'data-url\s*=\s*["\']([^"\']*' + escaped + r'[^"\']*)["\']',
    ]

    for pattern in href_patterns:
        try:
            found = re.findall(pattern, context, re.IGNORECASE)
            urls.update(found)
        except re.error:
            pass

    url_pattern = (
        r'(https?://[^\s"\'<>]*'
        + escaped
        + r'[^\s"\'<>]*)'
    )
    try:
        found = re.findall(url_pattern, context, re.IGNORECASE)
        urls.update(found)
    except re.error:
        pass

    return urls


# ─────────────────────────────────────────────
# Smart regex application with metadata
# ─────────────────────────────────────────────
def apply_smart_regex(bodies, pattern, exclude_keywords):
    """
    Returns: list of (url, matched_by, source_url, title, date)
    """
    results = []
    seen = set()

    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        st.error(f"Invalid regex: `{pattern}`\nError: {e}")
        return results

    exc_lower = [e.strip().lower() for e in exclude_keywords if e.strip()]
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

        try:
            p = urlparse(req_url)
            base_url = f"{p.scheme}://{p.netloc}"
        except Exception:
            base_url = ""

        for match_obj in compiled.finditer(body):
            if match_obj.lastindex and match_obj.lastindex >= 1:
                matched_text = match_obj.group(1)
            else:
                matched_text = match_obj.group(0)

            if not matched_text or len(matched_text) < 3:
                continue

            match_start = match_obj.start()

            cleaned = clean_url(matched_text)

            if cleaned:
                if cleaned not in seen:
                    if not any(e in cleaned.lower() for e in all_exc):
                        seen.add(cleaned)
                        title, date = extract_metadata_from_context(
                            body, cleaned, match_start
                        )
                        results.append((
                            cleaned, "regex-direct",
                            req_url, title, date
                        ))
                continue

            surrounding = find_urls_around_match(
                body, matched_text, match_start
            )

            for raw_url in surrounding:
                c = clean_url(raw_url)
                if not c:
                    if raw_url.startswith('/') and base_url:
                        c = base_url + raw_url
                    else:
                        continue

                if c not in seen:
                    if not any(e in c.lower() for e in all_exc):
                        seen.add(c)
                        title, date = extract_metadata_from_context(
                            body, c, match_start
                        )
                        results.append((
                            c, "regex-context",
                            req_url, title, date
                        ))

    results.sort(key=lambda x: x[0].split('/')[-1].lower())
    return results


# ─────────────────────────────────────────────
# Keyword filter with metadata
# ─────────────────────────────────────────────
def apply_keyword_filter(bodies, include_keywords, exclude_keywords):
    """
    Returns: list of (url, matched_by, source_url, title, date)
    """
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

        if '<' in body and '>' in body:
            found_urls.update(extract_urls_from_html(body, base))

        raw = re.findall(r'https?://[^\s"\'<>\\,;\]})]+', body)
        found_urls.update(raw)

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
                # Find position in body for context
                pos = body.find(raw_url)
                if pos == -1:
                    pos = body.find(cleaned)
                if pos == -1:
                    pos = 0

                title, date = extract_metadata_from_context(
                    body, cleaned, pos
                )
                results.append((
                    cleaned, f"keyword: {matched}",
                    req_url, title, date
                ))

    results.sort(key=lambda x: x[0].split('/')[-1].lower())
    return results


# ─────────────────────────────────────────────
# Generate output files
# ─────────────────────────────────────────────
def generate_html_links(results):
    """
    Generate <a href="URL">Title | Date</a> format.
    One per line.
    """
    lines = []
    for item in results:
        url = item[0]
        title = item[3] if len(item) > 3 else ""
        date = item[4] if len(item) > 4 else ""

        # Build display text
        fname = url.split('/')[-1].split('?')[0]
        if not fname:
            fname = url.split('/')[-2] if '/' in url else "link"

        display_parts = []
        if title:
            display_parts.append(title)
        else:
            # Use filename as fallback title
            clean_fname = fname.replace('.pdf', '').replace('.xlsx', '')
            clean_fname = clean_fname.replace('-', ' ').replace('_', ' ')
            display_parts.append(clean_fname.strip() or fname)

        if date:
            display_parts.append(date)

        display_text = " | ".join(display_parts)

        lines.append(f'<a href="{url}">{display_text}</a>')

    return "\n".join(lines)


def generate_full_report(results, source, inc_kw, exc_kw,
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

    lines.extend(["=" * 70, ""])
    lines.append("── HTML LINKS WITH TITLES & DATES ──")
    lines.append("")

    for i, item in enumerate(results, 1):
        url = item[0]
        matched_by = item[1]
        title = item[3] if len(item) > 3 else ""
        date = item[4] if len(item) > 4 else ""

        fname = url.split('/')[-1].split('?')[0]
        if not fname:
            fname = "link"

        display_parts = []
        if title:
            display_parts.append(title)
        else:
            display_parts.append(fname)
        if date:
            display_parts.append(date)

        display = " | ".join(display_parts)

        lines.append(f'{i:4d}. <a href="{url}">{display}</a>')
        lines.append(f"      Title: {title or '(from filename)'}")
        lines.append(f"      Date:  {date or '(not found)'}")
        lines.append(f"      Match: {matched_by}")
        lines.append("")

    lines.extend(["=" * 70, ""])
    lines.append("── PLAIN URL LIST ──")
    lines.append("")
    for item in results:
        lines.append(item[0])

    lines.extend(["", "=" * 70, "END"])
    return "\n".join(lines)


# ═════════════════════════════════════════════
# UI
# ═════════════════════════════════════════════

st.title("📄 HAR → URL Extractor")
st.markdown(
    "Upload `.har` → Extract URLs with **titles & dates** "
    "→ Download as `<a href>` format"
)

with st.expander("📖 How to capture .har file"):
    st.markdown("""
    1. Chrome → target website → F12 → Network tab
    2. Check **"Preserve log"**
    3. **Click ALL tabs/buttons** on the page
    4. Right-click in Network → **Save all as HAR with content**
    5. Upload here
    """)

st.markdown("---")
uploaded_file = st.file_uploader("📁 Upload .har file", type=['har'])

# ─── Settings ───
st.markdown("---")
st.subheader("🔧 Extraction Settings")

kw1, kw2 = st.columns(2)
with kw1:
    st.markdown("**✅ Include Keywords** (URL must contain ≥1)")
    include_input = st.text_input(
        "Keywords (| separated)",
        value=".pdf",
        placeholder=".pdf|/download/|.xlsx",
        key="inc"
    )
with kw2:
    st.markdown("**❌ Exclude Keywords**")
    exclude_input = st.text_input(
        "Exclude (| separated)",
        value=".jpg|.jpeg|.png|.gif|.svg|.webp|.ico|.css|.woff|.woff2",
        key="exc"
    )

st.markdown("---")
st.subheader("🔍 Regex Patterns (Smart)")
st.caption(
    "Type a simple keyword OR a full regex. "
    "The app finds the URL automatically."
)

rx1, rx2 = st.columns(2)
with rx1:
    st.markdown("**📄 PDF / Document Regex**")
    pdf_regex = st.text_input(
        "PDF regex", value="",
        placeholder=r'\.pdf|annual-report',
        key="pdf_rx"
    )
with rx2:
    st.markdown("**🌐 HTML / Page Link Regex**")
    html_regex = st.text_input(
        "HTML regex", value="",
        placeholder="communique-de-presse",
        key="html_rx"
    )

include_keywords = [
    kw.strip() for kw in include_input.split('|') if kw.strip()
]
exclude_keywords = [
    kw.strip() for kw in exclude_input.split('|') if kw.strip()
]

parts = []
if include_keywords:
    parts.append(f"Keywords: `{'`, `'.join(include_keywords)}`")
if pdf_regex.strip():
    parts.append(f"PDF regex: `{pdf_regex.strip()}`")
if html_regex.strip():
    parts.append(f"HTML regex: `{html_regex.strip()}`")
st.info(
    f"**Active:** {' | '.join(parts)}" if parts else
    "**⚠️ No filters set**"
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

        with st.spinner("Parsing HAR file..."):
            bodies, parse_log = parse_har_bodies(har_content)
            st.session_state.body_texts = bodies
            st.session_state.extraction_log = parse_log

        all_results = []
        seen = set()

        if include_keywords:
            with st.spinner(f"Keywords: {include_keywords}..."):
                for item in apply_keyword_filter(
                    bodies, include_keywords, exclude_keywords
                ):
                    if item[0] not in seen:
                        seen.add(item[0])
                        all_results.append(item)

        if pdf_regex.strip():
            with st.spinner(f"PDF regex: {pdf_regex}..."):
                for item in apply_smart_regex(
                    bodies, pdf_regex.strip(), exclude_keywords
                ):
                    if item[0] not in seen:
                        seen.add(item[0])
                        all_results.append((
                            item[0], f"pdf-{item[1]}",
                            item[2], item[3], item[4]
                        ))

        if html_regex.strip():
            with st.spinner(f"HTML regex: {html_regex}..."):
                for item in apply_smart_regex(
                    bodies, html_regex.strip(), exclude_keywords
                ):
                    if item[0] not in seen:
                        seen.add(item[0])
                        all_results.append((
                            item[0], f"html-{item[1]}",
                            item[2], item[3], item[4]
                        ))

        all_results.sort(
            key=lambda x: x[0].split('/')[-1].lower()
        )
        st.session_state.filtered_links = all_results
        st.session_state.har_loaded = True

        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("🔑 Keyword",
                       len([r for r in all_results if 'keyword' in r[1]]))
        with m2:
            st.metric("📄 PDF Regex",
                       len([r for r in all_results if 'pdf' in r[1]]))
        with m3:
            st.metric("🌐 HTML Regex",
                       len([r for r in all_results if 'html' in r[1]]))
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
            for item in apply_keyword_filter(
                bodies, include_keywords, exclude_keywords
            ):
                if item[0] not in seen:
                    seen.add(item[0])
                    all_results.append(item)
        if pdf_regex.strip():
            for item in apply_smart_regex(
                bodies, pdf_regex.strip(), exclude_keywords
            ):
                if item[0] not in seen:
                    seen.add(item[0])
                    all_results.append((
                        item[0], f"pdf-{item[1]}",
                        item[2], item[3], item[4]
                    ))
        if html_regex.strip():
            for item in apply_smart_regex(
                bodies, html_regex.strip(), exclude_keywords
            ):
                if item[0] not in seen:
                    seen.add(item[0])
                    all_results.append((
                        item[0], f"html-{item[1]}",
                        item[2], item[3], item[4]
                    ))

        all_results.sort(
            key=lambda x: x[0].split('/')[-1].lower()
        )
        st.session_state.filtered_links = all_results
        st.rerun()

    # Display
    for i, item in enumerate(st.session_state.filtered_links, 1):
        url = item[0]
        matched_by = item[1]
        title = item[3] if len(item) > 3 and item[3] else ""
        date = item[4] if len(item) > 4 and item[4] else ""

        fname = url.split('/')[-1].split('?')[0]
        if not fname:
            fname = url[:50]

        c1, c2, c3, c4, c5 = st.columns([0.3, 2.5, 1.2, 3.5, 1.5])
        with c1:
            st.text(f"{i}.")
        with c2:
            display = title if title else fname
            if len(display) > 50:
                display = display[:47] + "..."
            st.text(f"📄 {display}")
        with c3:
            st.text(f"📅 {date}" if date else "📅 —")
        with c4:
            st.markdown(f"[Open Link]({url})")
        with c5:
            st.caption(matched_by)

    # ─── Downloads ───
    st.markdown("---")
    st.header("⬇️ Download")

    d1, d2, d3, d4 = st.columns(4)

    with d1:
        html_out = generate_html_links(
            st.session_state.filtered_links
        )
        st.download_button(
            '📝 HTML Links (.txt)',
            data=html_out,
            file_name=(
                f"links_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            ),
            mime="text/plain",
            type="primary",
            help='<a href="URL">Title | Date</a> format'
        )

    with d2:
        plain = "\n".join(
            u for u, *_ in st.session_state.filtered_links
        )
        st.download_button(
            "🔗 Plain URLs (.txt)",
            data=plain,
            file_name=(
                f"urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            ),
            mime="text/plain"
        )

    with d3:
        report = generate_full_report(
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

    with d4:
        csv_lines = ["index,title,date,url,matched_by"]
        for i, item in enumerate(
            st.session_state.filtered_links, 1
        ):
            url = item[0]
            title = (item[3] if len(item) > 3 and item[3]
                     else "").replace('"', "'")
            date = (item[4] if len(item) > 4 and item[4]
                    else "").replace('"', "'")
            mb = item[1].replace('"', "'")
            csv_lines.append(
                f'{i},"{title}","{date}","{url}","{mb}"'
            )
        st.download_button(
            "📊 CSV (.csv)",
            data="\n".join(csv_lines),
            file_name=(
                f"data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            ),
            mime="text/csv"
        )

    # Copy section
    st.markdown("---")
    st.subheader("📋 Copy-Paste")

    tab_html, tab_plain = st.tabs([
        "HTML Links", "Plain URLs"
    ])

    with tab_html:
        html_out = generate_html_links(
            st.session_state.filtered_links
        )
        st.text_area(
            '<a href="URL">Title | Date</a> format',
            value=html_out,
            height=250,
            key="copy_html"
        )

    with tab_plain:
        plain = "\n".join(
            u for u, *_ in st.session_state.filtered_links
        )
        st.text_area(
            "Plain URLs",
            value=plain,
            height=250,
            key="copy_plain"
        )


# ─── Debug ───
if st.session_state.har_loaded:
    st.markdown("---")
    st.subheader("🔧 Debug: Search Response Bodies")

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
                        st.code(body[start:end], language="html")
                    if count >= 15:
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

    st.markdown("### Keywords")
    st.code(".pdf", language="text")
    st.code("communique-de-presse", language="text")
    st.code(".pdf|.xlsx|annual-report", language="text")

    st.markdown("### Regex")
    st.code(r'href="([^"]*investor[^"]*)"', language="text")
    st.code(r'communique-de-presse', language="text")
    st.code(r'<td[^>]*>(https?://[^<]+)</td>', language="text")

    st.markdown("---")
    st.markdown("""
    ### Output Format
    ```
    <a href="URL">Title | Date</a>
    ```
    
    ### Dates Extracted From
    - Nearby HTML elements
    - `<time>` tags
    - JSON date fields
    - URL path (/2025/01/)
    - Filename (Report-March2024)
    """)

    st.markdown("---")
    if st.button("🗑️ Clear"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()
