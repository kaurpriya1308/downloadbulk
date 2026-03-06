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
    r'\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}',
    r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}',
    r'\d{4}-\d{2}-\d{2}',
    r'\d{1,2}/\d{1,2}/\d{4}',
    r'\d{1,2}-\d{1,2}-\d{4}',
    r'\d{1,2}\.\d{1,2}\.\d{4}',
    r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}',
    r'Q[1-4]\s*(?:FY)?\s*\d{4}',
    r'FY\s*\d{4}(?:-\d{2,4})?',
    r'\d{4}-\d{2,4}',
]
DATE_REGEX = re.compile(
    '(' + '|'.join(DATE_PATTERNS) + ')', re.IGNORECASE
)


# ─────────────────────────────────────────────
# Unescape JSON string
# ─────────────────────────────────────────────
def unescape_json_string(text):
    if not text or not isinstance(text, str):
        return ""
    s = text
    s = s.replace('\\u003c', '<').replace('\\u003e', '>')
    s = s.replace('\\u0026', '&').replace('\\u003d', '=')
    s = s.replace('\\u0022', '"').replace('\\u0027', "'")
    for _ in range(5):
        old = s
        s = s.replace('\\"', '"').replace('\\/', '/')
        s = s.replace('\\\\', '\\').replace('\\n', '\n')
        s = s.replace('\\r', '\r').replace('\\t', '\t')
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
        cleaned = cleaned.replace('\\/', '/').replace('\\\\/', '/')
        cleaned = cleaned.replace('\\"', '').replace('\\n', '')
        cleaned = cleaned.replace('\\r', '').replace('\\u0026', '&')
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
# Extract metadata (title + date) from context
# ─────────────────────────────────────────────
def extract_metadata_from_context(body, url, match_start):
    title = ""
    date = ""
    ws = max(0, match_start - 1000)
    we = min(len(body), match_start + len(url) + 1000)
    context = body[ws:we]
    url_tail = url.split('/')[-1] if '/' in url else url
    et = re.escape(url_tail)

    # TITLE
    for pat in [
        r'<a[^>]*href\s*=\s*["\'][^"\']*' + et + r'[^"\']*["\'][^>]*>\s*(.*?)\s*</a>',
        r'href\s*=\s*["\'][^"\']*' + et + r'[^"\']*["\'][^>]*>\s*([^<]+)',
    ]:
        try:
            m = re.search(pat, context, re.IGNORECASE | re.DOTALL)
            if m:
                raw = re.sub(r'<[^>]+>', ' ', m.group(1))
                raw = re.sub(r'\s+', ' ', raw).strip()
                if raw and len(raw) > 2:
                    title = raw
                    break
        except re.error:
            pass

    if not title:
        try:
            m = re.search(
                r'<a[^>]*href\s*=\s*["\'][^"\']*' + et +
                r'[^"\']*["\'][^>]*title\s*=\s*["\']([^"\']+)["\']',
                context, re.IGNORECASE
            )
            if m:
                title = m.group(1).strip()
        except re.error:
            pass

    if not title:
        try:
            for mt in re.findall(
                r'<(?:h[1-6]|strong|b)[^>]*>\s*([^<]+?)\s*</(?:h[1-6]|strong|b)>',
                context, re.IGNORECASE
            ):
                mt = mt.strip()
                if mt and 3 < len(mt) < 200:
                    title = mt
                    break
        except re.error:
            pass

    if not title:
        try:
            for mt in re.findall(
                r'<(?:div|span)[^>]*class\s*=\s*["\'][^"\']*'
                r'(?:title|name|heading|label)[^"\']*["\'][^>]*>\s*([^<]+?)\s*</(?:div|span)>',
                context, re.IGNORECASE
            ):
                mt = mt.strip()
                if mt and 3 < len(mt) < 200:
                    title = mt
                    break
        except re.error:
            pass

    if not title:
        try:
            soup = BeautifulSoup(context, 'html.parser')
            for a in soup.find_all('a', href=True):
                h = a.get('href', '')
                if url_tail in h or url in h:
                    lt = a.get_text(strip=True)
                    if lt and len(lt) > 2:
                        title = lt
                        break
                    t = a.get('title', '').strip()
                    if t:
                        title = t
                        break
            if not title:
                for a in soup.find_all('a', href=True):
                    h = a.get('href', '')
                    if url_tail in h or url in h:
                        parent = a.parent
                        while parent and parent.name:
                            for sib in parent.children:
                                if sib == a:
                                    continue
                                if hasattr(sib, 'get_text'):
                                    st2 = sib.get_text(strip=True)
                                    if st2 and 3 < len(st2) < 200 and not st2.startswith('http'):
                                        title = st2
                                        break
                            if title:
                                break
                            parent = parent.parent
                            if parent and parent.name in ['body', 'html', 'main']:
                                break
        except Exception:
            pass

    # DATE
    dm = DATE_REGEX.findall(context)
    if dm:
        date = dm[0].strip()

    if not date:
        for pat in [
            r'<(?:time|span|div)[^>]*(?:class|datetime)\s*=\s*["\'][^"\']*(?:date|time|published)[^"\']*["\'][^>]*>\s*([^<]+)',
            r'<time[^>]*datetime\s*=\s*["\']([^"\']+)["\']',
            r'<(?:span|div)[^>]*class\s*=\s*["\'][^"\']*date[^"\']*["\'][^>]*>\s*([^<]+)',
        ]:
            try:
                m = re.search(pat, context, re.IGNORECASE)
                if m:
                    d = m.group(1).strip()
                    if d and len(d) < 50:
                        date = d
                        break
            except re.error:
                pass

    if not date:
        try:
            soup = BeautifulSoup(context, 'html.parser')
            for tt in soup.find_all('time'):
                dt = tt.get('datetime', '')
                if dt:
                    date = dt.strip()
                    break
                t = tt.get_text(strip=True)
                if t:
                    date = t
                    break
            if not date:
                for tag in soup.find_all(
                    class_=re.compile(r'date|time|publish|posted', re.IGNORECASE)
                ):
                    t = tag.get_text(strip=True)
                    if t and len(t) < 50 and DATE_REGEX.search(t):
                        date = t
                        break
        except Exception:
            pass

    if not date:
        try:
            m = re.search(
                r'"(?:date|published|created|updated|timestamp|publishDate|'
                r'createdAt|release_date|filing_date)"\s*:\s*"([^"]+)"',
                context, re.IGNORECASE
            )
            if m:
                date = m.group(1).strip()
        except re.error:
            pass

    if not date:
        ud = re.search(r'/(\d{4})[/-](\d{2})(?:[/-](\d{2}))?/', url)
        if ud:
            y, mo = ud.group(1), ud.group(2)
            da = ud.group(3)
            date = f"{y}-{mo}-{da}" if da else f"{y}-{mo}"

    if not date:
        fn = url.split('/')[-1]
        fd = re.search(
            r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[-_]?\d{4}',
            fn, re.IGNORECASE
        )
        if fd:
            date = fd.group(0)
        if not date:
            fd2 = re.search(r'(\d{4})[-_]?(\d{2})[-_]?(\d{2})', fn)
            if fd2 and 2000 <= int(fd2.group(1)) <= 2030:
                date = f"{fd2.group(1)}-{fd2.group(2)}-{fd2.group(3)}"

    if title:
        title = re.sub(r'<[^>]+>', '', title)
        title = re.sub(r'\s+', ' ', title).strip().strip('|/-:. ')
        if len(title) > 150:
            title = title[:147] + "..."
    if date:
        date = date.strip('|/-:,. ')
        date = re.sub(r'T\d{2}:\d{2}.*$', '', date).strip()

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
    for attr in [
        'href', 'src', 'data-href', 'data-src', 'data-url',
        'data-file', 'data-download', 'data-pdf', 'data-link',
        'action', 'content',
    ]:
        for tag in soup.find_all(attrs={attr: True}):
            val = tag.get(attr, '').strip()
            if val and not val.startswith(('#', 'javascript:', 'mailto:')):
                if val.startswith('http'):
                    urls.add(val)
                elif val.startswith('//'):
                    urls.add('https:' + val)
                elif val.startswith('/') and base_url:
                    urls.add(urljoin(base_url, val))
    for tag in soup.find_all(True):
        if tag.string:
            urls.update(re.findall(r'https?://[^\s<>"\']+', tag.string))
    for attr in ['onclick', 'onmousedown']:
        for tag in soup.find_all(attrs={attr: True}):
            urls.update(re.findall(r'["\']?(https?://[^\s"\'<>)]+)', tag.get(attr, '')))
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
        req_url = entry.get('request', {}).get('url', '')
        content = entry.get('response', {}).get('content', {})
        body = content.get('text', '')
        if not body or len(body) < 20:
            continue
        mime = content.get('mimeType', '').lower()
        unescaped = unescape_json_string(body)
        bodies.append((mime, req_url, unescaped))
        if 'json' in mime or unescaped.strip().startswith(('{', '[')):
            try:
                data = json.loads(unescaped)
                for frag in extract_html_from_json(data):
                    cf = unescape_json_string(frag)
                    if '<' in cf and '>' in cf:
                        bodies.append(('text/html (from json)', req_url, cf))
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
        indicators = ['<a ', '<a\n', '<div', '<span', '<td', '<tr',
                       '<table', '<p ', '<p>', '<li', 'href=', 'src=']
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
    ws = max(0, match_start - 500)
    we = min(len(body), match_start + len(match_text) + 500)
    ctx = body[ws:we]
    esc = re.escape(match_text)
    for pat in [
        r'href\s*=\s*["\']([^"\']*' + esc + r'[^"\']*)["\']',
        r'src\s*=\s*["\']([^"\']*' + esc + r'[^"\']*)["\']',
        r'data-url\s*=\s*["\']([^"\']*' + esc + r'[^"\']*)["\']',
    ]:
        try:
            urls.update(re.findall(pat, ctx, re.IGNORECASE))
        except re.error:
            pass
    try:
        urls.update(re.findall(
            r'(https?://[^\s"\'<>]*' + esc + r'[^\s"\'<>]*)',
            ctx, re.IGNORECASE
        ))
    except re.error:
        pass
    return urls


# ─────────────────────────────────────────────
# Smart regex with metadata
# ─────────────────────────────────────────────
def apply_smart_regex(bodies, pattern, exclude_keywords):
    results = []
    seen = set()
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        st.error(f"Invalid regex: `{pattern}`\nError: {e}")
        return results
    exc_lower = [e.strip().lower() for e in exclude_keywords if e.strip()]
    auto_exc = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico',
                '.css', '.woff', '.woff2', '.ttf', '.mp4', '.mp3', '.webm',
                'google-analytics', 'googletagmanager', 'doubleclick.net']
    all_exc = exc_lower + auto_exc
    for mime, req_url, body in bodies:
        if not body:
            continue
        try:
            base_url = f"{urlparse(req_url).scheme}://{urlparse(req_url).netloc}"
        except Exception:
            base_url = ""
        for mo in compiled.finditer(body):
            matched = mo.group(1) if mo.lastindex and mo.lastindex >= 1 else mo.group(0)
            if not matched or len(matched) < 3:
                continue
            ms = mo.start()
            cleaned = clean_url(matched)
            if cleaned:
                if cleaned not in seen and not any(e in cleaned.lower() for e in all_exc):
                    seen.add(cleaned)
                    title, date = extract_metadata_from_context(body, cleaned, ms)
                    results.append((cleaned, "regex-direct", req_url, title, date))
                continue
            for raw in find_urls_around_match(body, matched, ms):
                c = clean_url(raw)
                if not c and raw.startswith('/') and base_url:
                    c = base_url + raw
                if c and c not in seen and not any(e in c.lower() for e in all_exc):
                    seen.add(c)
                    title, date = extract_metadata_from_context(body, c, ms)
                    results.append((c, "regex-context", req_url, title, date))
    results.sort(key=lambda x: x[0].split('/')[-1].lower())
    return results


# ─────────────────────────────────────────────
# Keyword filter with metadata
# ─────────────────────────────────────────────
def apply_keyword_filter(bodies, include_keywords, exclude_keywords):
    results = []
    seen = set()
    inc = [kw.strip().lower() for kw in include_keywords if kw.strip()]
    exc = [kw.strip().lower() for kw in exclude_keywords if kw.strip()]
    auto_exc = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico',
                '.css', '.woff', '.woff2', '.ttf', '.mp4', '.mp3', '.webm',
                'google-analytics', 'googletagmanager', 'doubleclick.net']
    all_exc = exc + auto_exc
    for mime, req_url, body in bodies:
        if not body:
            continue
        try:
            base = f"{urlparse(req_url).scheme}://{urlparse(req_url).netloc}"
        except Exception:
            base = ""
        found_urls = set()
        if '<' in body and '>' in body:
            found_urls.update(extract_urls_from_html(body, base))
        found_urls.update(re.findall(r'https?://[^\s"\'<>\\,;\]})]+', body))
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
                pos = body.find(raw_url)
                if pos == -1:
                    pos = body.find(cleaned)
                if pos == -1:
                    pos = 0
                title, date = extract_metadata_from_context(body, cleaned, pos)
                results.append((cleaned, f"keyword: {matched}", req_url, title, date))
    results.sort(key=lambda x: x[0].split('/')[-1].lower())
    return results


# ─────────────────────────────────────────────
# Output generators
# ─────────────────────────────────────────────
def generate_html_links_txt(results):
    lines = []
    for item in results:
        url = item[0]
        title = item[3] if len(item) > 3 and item[3] else ""
        date = item[4] if len(item) > 4 and item[4] else ""
        fname = url.split('/')[-1].split('?')[0]
        if not fname:
            fname = url.split('/')[-2] if '/' in url else "link"
        parts = []
        if title:
            parts.append(title)
        else:
            cf = fname.replace('.pdf', '').replace('.xlsx', '')
            cf = cf.replace('-', ' ').replace('_', ' ').strip()
            parts.append(cf or fname)
        if date:
            parts.append(date)
        display = " | ".join(parts)
        lines.append(f'<a href="{url}">{display}</a>')
    return "\n".join(lines)


def generate_full_report(results, source, inc_kw, exc_kw,
                         pdf_regex="", html_regex=""):
    lines = ["=" * 70, "URL EXTRACTION REPORT", "=" * 70,
             f"Source       : {source}",
             f"Date         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
             f"Total URLs   : {len(results)}"]
    if inc_kw:
        lines.append(f"Keywords     : {', '.join(inc_kw)}")
    if pdf_regex:
        lines.append(f"PDF Regex    : {pdf_regex}")
    if html_regex:
        lines.append(f"HTML Regex   : {html_regex}")
    lines.append(f"Excludes     : {len(exc_kw)} patterns")
    lines.extend(["=" * 70, "", "── HTML LINKS WITH TITLES & DATES ──", ""])
    for i, item in enumerate(results, 1):
        url = item[0]
        mb = item[1]
        title = item[3] if len(item) > 3 and item[3] else ""
        date = item[4] if len(item) > 4 and item[4] else ""
        fname = url.split('/')[-1].split('?')[0] or "link"
        parts = [title if title else fname]
        if date:
            parts.append(date)
        display = " | ".join(parts)
        lines.append(f'{i:4d}. <a href="{url}">{display}</a>')
        lines.append(f"      Title: {title or '(from filename)'}")
        lines.append(f"      Date:  {date or '(not found)'}")
        lines.append(f"      Match: {mb}")
        lines.append("")
    lines.extend(["=" * 70, "", "── PLAIN URL LIST ──", ""])
    for item in results:
        lines.append(item[0])
    lines.extend(["", "=" * 70, "END"])
    return "\n".join(lines)


def generate_html_file(results, source="", inc_kw=None,
                       pdf_regex="", html_regex=""):
    total = len(results)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    kw_str = ', '.join(inc_kw) if inc_kw else 'None'

    rows_html = ""
    for i, item in enumerate(results, 1):
        url = item[0]
        title = item[3] if len(item) > 3 and item[3] else ""
        date = item[4] if len(item) > 4 and item[4] else ""
        matched_by = item[1]
        fname = url.split('/')[-1].split('?')[0]
        if not fname:
            fname = url.split('/')[-2] if '/' in url else "link"
        dt = (title if title else fname).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        eu = url.replace('&', '&amp;').replace('"', '&quot;')
        sj = url.replace("'", "\\'").replace('"', '\\"')
        dd = date or '—'
        md = matched_by.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        rows_html += f"""
        <tr>
            <td class="num">{i}</td>
            <td class="title">{dt}</td>
            <td class="date">{dd}</td>
            <td class="link"><a href="{eu}" target="_blank" rel="noopener noreferrer">{fname}</a></td>
            <td class="matched">{md}</td>
            <td class="actions"><button onclick="copyUrl('{sj}')" title="Copy URL">📋</button></td>
        </tr>"""

    all_href_lines = ""
    for item in results:
        url = item[0]
        title = item[3] if len(item) > 3 and item[3] else ""
        date = item[4] if len(item) > 4 and item[4] else ""
        fname = url.split('/')[-1].split('?')[0] or "link"
        display = title if title else fname
        if date:
            display += f" | {date}"
        eu = url.replace('&', '&amp;').replace('"', '&quot;')
        display = display.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        all_href_lines += f'&lt;a href="{eu}"&gt;{display}&lt;/a&gt;\n'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Extracted URLs — {now}</title>
    <style>
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f7fa;color:#333;padding:20px}}
        .container{{max-width:1400px;margin:0 auto}}
        header{{background:linear-gradient(135deg,#1a73e8,#0d47a1);color:#fff;padding:24px 32px;border-radius:12px;margin-bottom:20px}}
        header h1{{font-size:24px;margin-bottom:8px}}
        header .meta{{font-size:13px;opacity:.85;display:flex;flex-wrap:wrap;gap:16px}}
        .stats{{display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap}}
        .stat-card{{background:#fff;border-radius:8px;padding:16px 24px;box-shadow:0 1px 3px rgba(0,0,0,.08);text-align:center;min-width:120px}}
        .stat-card .number{{font-size:28px;font-weight:700;color:#1a73e8}}
        .stat-card .label{{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.5px}}
        .controls{{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center}}
        .search-box{{flex:1;min-width:250px;padding:10px 16px;border:2px solid #ddd;border-radius:8px;font-size:14px;outline:none}}
        .search-box:focus{{border-color:#1a73e8}}
        .btn{{padding:10px 18px;border:none;border-radius:8px;cursor:pointer;font-size:13px;font-weight:500;transition:all .2s;white-space:nowrap}}
        .btn-primary{{background:#1a73e8;color:#fff}}.btn-primary:hover{{background:#1557b0}}
        .btn-secondary{{background:#e8eaed;color:#333}}.btn-secondary:hover{{background:#d2d5da}}
        .btn-success{{background:#0d904f;color:#fff}}.btn-success:hover{{background:#0a7a42}}
        .count-badge{{background:#e8f0fe;color:#1a73e8;padding:8px 16px;border-radius:8px;font-weight:600;font-size:14px}}
        .table-wrapper{{background:#fff;border-radius:12px;overflow-x:auto;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
        table{{width:100%;border-collapse:collapse}}
        thead th{{background:#f8f9fa;padding:12px 14px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#666;border-bottom:2px solid #e8eaed;cursor:pointer;user-select:none;white-space:nowrap}}
        thead th:hover{{background:#e8eaed}}
        thead th .sort-icon{{margin-left:4px;opacity:.4}}
        tbody td{{padding:10px 14px;border-bottom:1px solid #f0f0f0;font-size:13px;vertical-align:middle}}
        tbody tr:hover{{background:#f8f9fa}}
        tbody tr.hidden{{display:none}}
        .num{{width:40px;color:#999;text-align:center}}
        .title{{max-width:300px;word-break:break-word}}
        .date{{white-space:nowrap;color:#555;min-width:100px;font-weight:500}}
        .link{{max-width:350px;word-break:break-all}}
        .link a{{color:#1a73e8;text-decoration:none;font-size:12px}}
        .link a:hover{{text-decoration:underline}}
        .matched{{font-size:11px;color:#888;max-width:120px}}
        .actions{{width:50px;text-align:center}}
        .actions button{{background:none;border:1px solid #ddd;border-radius:4px;cursor:pointer;padding:4px 8px;font-size:14px}}
        .actions button:hover{{background:#e8f0fe;border-color:#1a73e8}}
        .toast{{position:fixed;bottom:20px;right:20px;background:#333;color:#fff;padding:12px 24px;border-radius:8px;font-size:14px;opacity:0;transition:opacity .3s;z-index:1000}}
        .toast.show{{opacity:1}}
        .href-section{{margin-top:24px;background:#fff;border-radius:12px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
        .href-section h3{{margin-bottom:12px;color:#333}}
        .href-box{{background:#f8f9fa;border:1px solid #e8eaed;border-radius:8px;padding:16px;font-family:Consolas,Monaco,monospace;font-size:12px;line-height:1.8;max-height:400px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}}
        @media(max-width:768px){{.controls{{flex-direction:column}}.search-box{{min-width:100%}}.stats{{flex-direction:column}}}}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📄 Extracted URLs</h1>
            <div class="meta">
                <span>📁 {source}</span><span>📅 {now}</span><span>🔗 {total} URLs</span><span>🔑 {kw_str}</span>
                {'<span>📄 '+pdf_regex+'</span>' if pdf_regex else ''}
                {'<span>🌐 '+html_regex+'</span>' if html_regex else ''}
            </div>
        </header>
        <div class="stats">
            <div class="stat-card"><div class="number">{total}</div><div class="label">Total</div></div>
            <div class="stat-card"><div class="number">{len([r for r in results if len(r)>4 and r[4]])}</div><div class="label">With Dates</div></div>
            <div class="stat-card"><div class="number">{len([r for r in results if len(r)>3 and r[3]])}</div><div class="label">With Titles</div></div>
            <div class="stat-card"><div class="number">{len([r for r in results if '.pdf' in r[0].lower()])}</div><div class="label">PDFs</div></div>
        </div>
        <div class="controls">
            <input type="text" class="search-box" id="searchBox" placeholder="🔍 Search..." oninput="filterTable()">
            <span class="count-badge" id="countBadge">{total} links</span>
            <button class="btn btn-primary" onclick="copyAllHrefs()">📋 Copy &lt;a href&gt;</button>
            <button class="btn btn-success" onclick="copyAllUrls()">🔗 Copy URLs</button>
            <button class="btn btn-secondary" onclick="exportVisible()">💾 Export Visible</button>
        </div>
        <div class="table-wrapper">
            <table id="urlTable">
                <thead><tr>
                    <th onclick="sortTable(0)"># <span class="sort-icon">↕</span></th>
                    <th onclick="sortTable(1)">Title <span class="sort-icon">↕</span></th>
                    <th onclick="sortTable(2)">Date <span class="sort-icon">↕</span></th>
                    <th onclick="sortTable(3)">Link <span class="sort-icon">↕</span></th>
                    <th onclick="sortTable(4)">Source <span class="sort-icon">↕</span></th>
                    <th>Copy</th>
                </tr></thead>
                <tbody id="tableBody">{rows_html}</tbody>
            </table>
        </div>
        <div class="href-section">
            <h3>📋 All Links as &lt;a href&gt; Tags</h3>
            <div style="margin-bottom:12px;display:flex;gap:8px">
                <button class="btn btn-primary" onclick="copyHrefBox()">Copy All</button>
                <button class="btn btn-secondary" onclick="downloadHrefTxt()">💾 Save .txt</button>
            </div>
            <div class="href-box" id="hrefBox">{all_href_lines}</div>
        </div>
    </div>
    <div class="toast" id="toast">Copied!</div>
    <script>
        function showToast(m){{const t=document.getElementById('toast');t.textContent=m||'Copied!';t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2000)}}
        function copyUrl(u){{navigator.clipboard.writeText(u).then(()=>showToast('URL copied!'))}}
        function copyAllHrefs(){{navigator.clipboard.writeText(document.getElementById('hrefBox').textContent).then(()=>showToast('All <a href> copied!'))}}
        function copyAllUrls(){{const u=[];document.querySelectorAll('#tableBody tr:not(.hidden)').forEach(r=>{{const a=r.querySelector('.link a');if(a)u.push(a.href)}});navigator.clipboard.writeText(u.join('\\n')).then(()=>showToast(u.length+' URLs copied!'))}}
        function copyHrefBox(){{navigator.clipboard.writeText(document.getElementById('hrefBox').textContent).then(()=>showToast('Copied!'))}}
        function filterTable(){{const q=document.getElementById('searchBox').value.toLowerCase();let v=0;document.querySelectorAll('#tableBody tr').forEach(r=>{{if(r.textContent.toLowerCase().includes(q)){{r.classList.remove('hidden');v++}}else{{r.classList.add('hidden')}}}});document.getElementById('countBadge').textContent=v+' links'}}
        let sd={{}};function sortTable(c){{const tb=document.getElementById('tableBody');const rows=Array.from(tb.querySelectorAll('tr'));sd[c]=!sd[c];const d=sd[c]?1:-1;rows.sort((a,b)=>{{let av=a.cells[c].textContent.trim(),bv=b.cells[c].textContent.trim();return c===0?(parseInt(av)-parseInt(bv))*d:av.localeCompare(bv)*d}});rows.forEach(r=>tb.appendChild(r))}}
        function exportVisible(){{let t='';document.querySelectorAll('#tableBody tr:not(.hidden)').forEach(r=>{{const ti=r.querySelector('.title').textContent.trim(),da=r.querySelector('.date').textContent.trim(),a=r.querySelector('.link a'),u=a?a.href:'',di=ti+(da!=='—'?' | '+da:'');t+='<a href="'+u+'">'+di+'</a>\\n'}});const b=new Blob([t],{{type:'text/plain'}});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='exported_links.txt';a.click();showToast('Exported!')}}
        function downloadHrefTxt(){{const b=new Blob([document.getElementById('hrefBox').textContent],{{type:'text/plain'}});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='href_links.txt';a.click();showToast('Downloaded!')}}
    </script>
</body>
</html>"""


# ═════════════════════════════════════════════
# STREAMLIT UI
# ═════════════════════════════════════════════

st.title("📄 HAR → URL Extractor")
st.markdown(
    "Upload `.har` → Extract URLs with **titles & dates** "
    "→ Download as `.txt` and `.html`"
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
        "Keywords (| separated)", value=".pdf",
        placeholder=".pdf|/download/|.xlsx", key="inc"
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
    "Type simple text OR full regex. "
    "App finds the URL automatically."
)

rx1, rx2 = st.columns(2)
with rx1:
    st.markdown("**📄 PDF / Document Regex**")
    pdf_regex = st.text_input(
        "PDF regex", value="",
        placeholder=r'\.pdf|annual-report', key="pdf_rx"
    )
with rx2:
    st.markdown("**🌐 HTML / Page Link Regex**")
    html_regex = st.text_input(
        "HTML regex", value="",
        placeholder="communique-de-presse", key="html_rx"
    )

include_keywords = [kw.strip() for kw in include_input.split('|') if kw.strip()]
exclude_keywords = [kw.strip() for kw in exclude_input.split('|') if kw.strip()]

parts = []
if include_keywords:
    parts.append(f"Keywords: `{'`, `'.join(include_keywords)}`")
if pdf_regex.strip():
    parts.append(f"PDF regex: `{pdf_regex.strip()}`")
if html_regex.strip():
    parts.append(f"HTML regex: `{html_regex.strip()}`")
st.info(f"**Active:** {' | '.join(parts)}" if parts else "**⚠️ No filters set**")

# ─── Extract ───
st.markdown("---")

if uploaded_file:
    try:
        har_content = uploaded_file.read().decode('utf-8')
    except UnicodeDecodeError:
        har_content = uploaded_file.read().decode('utf-8', errors='ignore')

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
                for item in apply_keyword_filter(bodies, include_keywords, exclude_keywords):
                    if item[0] not in seen:
                        seen.add(item[0])
                        all_results.append(item)

        if pdf_regex.strip():
            with st.spinner(f"PDF regex: {pdf_regex}..."):
                for item in apply_smart_regex(bodies, pdf_regex.strip(), exclude_keywords):
                    if item[0] not in seen:
                        seen.add(item[0])
                        all_results.append((item[0], f"pdf-{item[1]}", item[2], item[3], item[4]))

        if html_regex.strip():
            with st.spinner(f"HTML regex: {html_regex}..."):
                for item in apply_smart_regex(bodies, html_regex.strip(), exclude_keywords):
                    if item[0] not in seen:
                        seen.add(item[0])
                        all_results.append((item[0], f"html-{item[1]}", item[2], item[3], item[4]))

        all_results.sort(key=lambda x: x[0].split('/')[-1].lower())
        st.session_state.filtered_links = all_results
        st.session_state.har_loaded = True


# ─── Results (Downloads FIRST, then collapsible details) ───
if st.session_state.har_loaded and st.session_state.filtered_links:
    total = len(st.session_state.filtered_links)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # METRICS — always visible
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    st.markdown("---")
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("🔑 Keyword", len([r for r in st.session_state.filtered_links if 'keyword' in r[1]]))
    with m2:
        st.metric("📄 PDF Regex", len([r for r in st.session_state.filtered_links if 'pdf' in r[1]]))
    with m3:
        st.metric("🌐 HTML Regex", len([r for r in st.session_state.filtered_links if 'html' in r[1]]))
    with m4:
        st.metric("📊 Total", total)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # DOWNLOADS — always visible, RIGHT AFTER metrics
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    st.markdown("---")
    st.header(f"⬇️ Download {total} URLs")

    d1, d2, d3, d4, d5 = st.columns(5)

    with d1:
        st.download_button(
            '📝 Links (.txt)',
            data=generate_html_links_txt(st.session_state.filtered_links),
            file_name=f"links_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            type="primary",
            help='<a href="URL">Title | Date</a>'
        )

    with d2:
        st.download_button(
            "🌐 HTML Page (.html)",
            data=generate_html_file(
                st.session_state.filtered_links,
                source=uploaded_file.name if uploaded_file else "",
                inc_kw=include_keywords,
                pdf_regex=pdf_regex,
                html_regex=html_regex
            ),
            file_name=f"links_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            mime="text/html",
            help="Interactive page with search, sort, copy"
        )

    with d3:
        st.download_button(
            "🔗 URLs (.txt)",
            data="\n".join(u for u, *_ in st.session_state.filtered_links),
            file_name=f"urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )

    with d4:
        st.download_button(
            "📋 Report (.txt)",
            data=generate_full_report(
                st.session_state.filtered_links,
                uploaded_file.name if uploaded_file else "unknown",
                include_keywords, exclude_keywords,
                pdf_regex, html_regex
            ),
            file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )

    with d5:
        csv_lines = ["index,title,date,url,matched_by"]
        for i, item in enumerate(st.session_state.filtered_links, 1):
            t = (item[3] if len(item) > 3 and item[3] else "").replace('"', "'")
            da = (item[4] if len(item) > 4 and item[4] else "").replace('"', "'")
            mb = item[1].replace('"', "'")
            csv_lines.append(f'{i},"{t}","{da}","{item[0]}","{mb}"')
        st.download_button(
            "📊 CSV (.csv)",
            data="\n".join(csv_lines),
            file_name=f"data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # COPY-PASTE — collapsible
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    with st.expander("📋 Copy-Paste Ready", expanded=False):
        tab_html, tab_plain = st.tabs(["HTML Links", "Plain URLs"])
        with tab_html:
            st.text_area(
                '<a href="URL">Title | Date</a>',
                value=generate_html_links_txt(st.session_state.filtered_links),
                height=200, key="copy_html"
            )
        with tab_plain:
            st.text_area(
                "Plain URLs",
                value="\n".join(u for u, *_ in st.session_state.filtered_links),
                height=200, key="copy_plain"
            )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # FOUND LINKS — collapsible, CLOSED by default
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    with st.expander(f"📄 View All {total} Found Links", expanded=False):

        # Re-filter button inside the expander
        if st.button("🔄 Re-apply Filters", key="refilter"):
            bodies = st.session_state.body_texts
            all_results = []
            seen = set()
            if include_keywords:
                for item in apply_keyword_filter(bodies, include_keywords, exclude_keywords):
                    if item[0] not in seen:
                        seen.add(item[0])
                        all_results.append(item)
            if pdf_regex.strip():
                for item in apply_smart_regex(bodies, pdf_regex.strip(), exclude_keywords):
                    if item[0] not in seen:
                        seen.add(item[0])
                        all_results.append((item[0], f"pdf-{item[1]}", item[2], item[3], item[4]))
            if html_regex.strip():
                for item in apply_smart_regex(bodies, html_regex.strip(), exclude_keywords):
                    if item[0] not in seen:
                        seen.add(item[0])
                        all_results.append((item[0], f"html-{item[1]}", item[2], item[3], item[4]))
            all_results.sort(key=lambda x: x[0].split('/')[-1].lower())
            st.session_state.filtered_links = all_results
            st.rerun()

        # Display each link
        for i, item in enumerate(st.session_state.filtered_links, 1):
            url = item[0]
            matched_by = item[1]
            title = item[3] if len(item) > 3 and item[3] else ""
            date = item[4] if len(item) > 4 and item[4] else ""
            fname = url.split('/')[-1].split('?')[0] or url[:50]

            c1, c2, c3, c4, c5 = st.columns([0.3, 2.5, 1.2, 3.5, 1.5])
            with c1:
                st.text(f"{i}.")
            with c2:
                d = title if title else fname
                if len(d) > 50:
                    d = d[:47] + "..."
                st.text(f"📄 {d}")
            with c3:
                st.text(f"📅 {date}" if date else "📅 —")
            with c4:
                st.markdown(f"[Open Link]({url})")
            with c5:
                st.caption(matched_by)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # DEBUG — collapsible, CLOSED by default
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    with st.expander("🔧 Debug: Search Response Bodies", expanded=False):
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
                        with st.expander(f"{count}. [{mime[:30]}] {req_url[:80]}"):
                            idx = body.lower().find(body_search.lower())
                            start = max(0, idx - 300)
                            end = min(len(body), idx + 500)
                            st.code(body[start:end], language="html")
                        if count >= 15:
                            break
                if count:
                    st.success(f"Found in {count} response(s)")
                else:
                    st.warning(f"'{body_search}' not found")

    with st.expander("📋 Parse Log", expanded=False):
        if st.session_state.extraction_log:
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
    ### Download Formats
    - **📝 Links .txt** → `<a href>` tags
    - **🌐 HTML .html** → Interactive page
    - **🔗 URLs .txt** → Plain URLs
    - **📋 Report .txt** → Full details
    - **📊 CSV** → For Excel

    ### HTML File Features
    - 🔍 Search box
    - ↕️ Sortable columns
    - 📋 Copy buttons
    - 💾 Export filtered
    """)

    st.markdown("---")
    if st.button("🗑️ Clear"):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()
