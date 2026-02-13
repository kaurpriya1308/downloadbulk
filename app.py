import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import os
import time
import json
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
import zipfile
import subprocess
import sys

# ─────────────────────────────────────────────
# Page Configuration
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Smart PDF Downloader",
    page_icon="📥",
    layout="wide"
)

# ─────────────────────────────────────────────
# Install Playwright browsers on first run
# ─────────────────────────────────────────────
@st.cache_resource
def install_playwright():
    """Install playwright and chromium browser once"""
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "playwright"
        ])
        subprocess.check_call([
            sys.executable, "-m", "playwright", "install", "chromium"
        ])
        return True
    except Exception as e:
        st.error(f"Playwright install failed: {e}")
        return False


# ─────────────────────────────────────────────
# Session State
# ─────────────────────────────────────────────
if 'found_pdfs' not in st.session_state:
    st.session_state.found_pdfs = []
if 'downloaded_pdfs' not in st.session_state:
    st.session_state.downloaded_pdfs = {}
if 'txt_output' not in st.session_state:
    st.session_state.txt_output = ""
if 'scan_done' not in st.session_state:
    st.session_state.scan_done = False
if 'network_logs' not in st.session_state:
    st.session_state.network_logs = []
if 'json_responses' not in st.session_state:
    st.session_state.json_responses = []


# ─────────────────────────────────────────────
# Core Functions
# ─────────────────────────────────────────────

def get_session():
    """Create requests session with browser-like headers"""
    session = requests.Session()
    session.headers.update({
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        ),
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive',
    })
    return session


def extract_pdfs_from_html(url, session):
    """Method 1: Extract PDF links from HTML source"""
    pdf_links = set()

    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        for tag in soup.find_all('a', href=True):
            href = tag['href'].strip()
            if not href or href.startswith('#') or href.startswith('javascript'):
                continue

            absolute_url = urljoin(url, href)
            path_lower = urlparse(absolute_url).path.lower()

            if path_lower.endswith('.pdf'):
                pdf_links.add(absolute_url)
            elif '.pdf' in absolute_url.lower():
                pdf_links.add(absolute_url)

        # Check embeds, iframes, objects
        for tag in soup.find_all(['embed', 'iframe', 'object']):
            src = tag.get('src', '') or tag.get('data', '')
            if src and '.pdf' in src.lower():
                pdf_links.add(urljoin(url, src))

    except Exception as e:
        st.warning(f"HTML scan error: {e}")

    return pdf_links


def extract_pdfs_from_json(data, base_url):
    """
    Recursively search JSON response for PDF URLs.
    Works with any JSON structure — nested dicts, lists, etc.
    """
    pdf_links = set()

    def search(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str):
                    check_string(value, key)
                else:
                    search(value)

        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, str):
                    check_string(item)
                else:
                    search(item)

        elif isinstance(obj, str):
            check_string(obj)

    def check_string(value, key=""):
        """Check if a string value contains a PDF reference"""
        value = value.strip()
        if not value:
            return

        # Direct .pdf check
        if '.pdf' in value.lower():
            # Could be a full URL or relative path
            if value.startswith('http'):
                pdf_links.add(value)
            elif value.startswith('/'):
                pdf_links.add(urljoin(base_url, value))
            elif value.startswith('www.'):
                pdf_links.add('https://' + value)
            else:
                # Might be a relative path like "uploads/file.pdf"
                pdf_links.add(urljoin(base_url, '/' + value))

        # Check common keys that hold file URLs
        key_lower = key.lower()
        file_keys = [
            'url', 'file', 'path', 'link', 'href', 'src',
            'download', 'document', 'attachment', 'filepath',
            'fileurl', 'file_url', 'download_url', 'pdf',
            'report_url', 'doc_url', 'document_url'
        ]

        if any(fk in key_lower for fk in file_keys):
            if value.startswith('http') and any(
                ext in value.lower()
                for ext in ['.pdf', '.doc', '.xlsx', '.xls']
            ):
                pdf_links.add(value)
            elif value.startswith('/') and '.pdf' in value.lower():
                pdf_links.add(urljoin(base_url, value))

    search(data)
    return pdf_links


def intercept_network_for_pdfs(url, wait_time=10, click_tabs=True):
    """
    Method 2: Use Playwright to intercept ALL network requests.
    This captures:
    - XHR/Fetch API calls (JSON endpoints)
    - Dynamic PDF links loaded via JavaScript
    - Tab switches and lazy-loaded content
    """
    from playwright.sync_api import sync_playwright

    pdf_links = set()
    network_log = []
    json_responses = []
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu'
            ]
        )

        context = browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent=(
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            )
        )

        page = context.new_page()

        # ── Intercept ALL network responses ──
        def handle_response(response):
            """Capture every network response"""
            try:
                resp_url = response.url
                content_type = response.headers.get('content-type', '')

                # Log the request
                network_log.append({
                    'url': resp_url,
                    'status': response.status,
                    'type': content_type[:50]
                })

                # ── Check 1: Direct PDF file response ──
                if '.pdf' in resp_url.lower():
                    pdf_links.add(resp_url)
                    return

                if 'application/pdf' in content_type:
                    pdf_links.add(resp_url)
                    return

                # ── Check 2: JSON response containing PDF URLs ──
                if 'json' in content_type or 'javascript' in content_type:
                    try:
                        body = response.text()
                        data = json.loads(body)

                        json_responses.append({
                            'url': resp_url,
                            'data_preview': str(data)[:500]
                        })

                        # Extract PDFs from JSON
                        found = extract_pdfs_from_json(data, base_url)
                        pdf_links.update(found)

                    except (json.JSONDecodeError, Exception):
                        # Try regex on raw text for PDF URLs
                        try:
                            body = response.text()
                            # Find URLs ending in .pdf
                            pattern = r'https?://[^\s"\'<>]+\.pdf'
                            matches = re.findall(pattern, body)
                            pdf_links.update(matches)

                            # Find relative paths
                            pattern2 = r'["\'](/[^\s"\'<>]+\.pdf)["\']'
                            matches2 = re.findall(pattern2, body)
                            for m in matches2:
                                pdf_links.add(urljoin(base_url, m))
                        except Exception:
                            pass

                # ── Check 3: HTML response with PDF links ──
                elif 'html' in content_type:
                    try:
                        body = response.text()
                        pattern = r'https?://[^\s"\'<>]+\.pdf'
                        matches = re.findall(pattern, body)
                        pdf_links.update(matches)

                        pattern2 = r'href=["\']([^"\']+\.pdf)["\']'
                        matches2 = re.findall(pattern2, body)
                        for m in matches2:
                            pdf_links.add(urljoin(base_url, m))
                    except Exception:
                        pass

            except Exception:
                pass

        page.on("response", handle_response)

        # ── Load the page ──
        try:
            page.goto(url, wait_until="networkidle", timeout=30000)
        except Exception:
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                st.warning(f"Page load issue: {e}")

        # ── Wait for initial content ──
        time.sleep(wait_time)

        # ── Click on tabs/buttons to trigger more API calls ──
        if click_tabs:
            clickable_selectors = [
                # Common tab/button selectors
                'button',
                '[role="tab"]',
                '.tab',
                '.nav-link',
                '.nav-item',
                '.tab-link',
                '.accordion-button',
                '.accordion-header',
                '.collapse-toggle',
                'a[data-toggle="tab"]',
                'a[data-bs-toggle="tab"]',
                'li[role="presentation"]',
                '.MuiTab-root',
                '.ant-tabs-tab',
                '[class*="tab"]',
                '[class*="Tab"]',
            ]

            clicked_elements = set()

            for selector in clickable_selectors:
                try:
                    elements = page.query_selector_all(selector)
                    for element in elements:
                        try:
                            # Get element text to avoid clicking
                            # same content twice
                            text = element.inner_text().strip()[:50]
                            if text in clicked_elements:
                                continue
                            clicked_elements.add(text)

                            # Check if visible and clickable
                            if element.is_visible():
                                element.click()
                                # Wait for network response
                                time.sleep(2)

                        except Exception:
                            continue
                except Exception:
                    continue

        # ── Final wait for any remaining requests ──
        time.sleep(3)

        # ── Also scan final page HTML ──
        try:
            html_content = page.content()
            soup = BeautifulSoup(html_content, 'html.parser')

            for tag in soup.find_all('a', href=True):
                href = tag['href'].strip()
                if '.pdf' in href.lower():
                    pdf_links.add(urljoin(url, href))
        except Exception:
            pass

        browser.close()

    return pdf_links, network_log, json_responses


def download_single_pdf(pdf_url, session, index):
    """Download a single PDF file"""
    try:
        response = session.get(
            pdf_url,
            timeout=60,
            stream=True,
            allow_redirects=True
        )
        response.raise_for_status()

        # ── Determine filename ──
        filename = None

        # Try Content-Disposition header
        cd = response.headers.get('Content-Disposition', '')
        if 'filename' in cd:
            match = re.findall(
                r'filename[^;=\n]*=["\']?([^"\';\n]+)',
                cd
            )
            if match:
                filename = match[0].strip()

        # Fallback: URL path
        if not filename:
            parsed_path = urlparse(pdf_url).path
            filename = os.path.basename(parsed_path)

        # Fallback: generic name
        if not filename or len(filename) < 3:
            filename = f"document_{index:03d}.pdf"

        if not filename.lower().endswith('.pdf'):
            filename += '.pdf'

        # Clean filename
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        filename = filename.strip()

        content = response.content

        # Verify PDF
        content_type = response.headers.get('Content-Type', '').lower()
        is_pdf = (
            content[:4] == b'%PDF'
            or 'pdf' in content_type
        )

        if not is_pdf and len(content) < 1000:
            return (filename, None, False, "Not a valid PDF")

        return (filename, content, True, None)

    except Exception as e:
        return (f"document_{index:03d}.pdf", None, False, str(e))


def download_all_pdfs(pdf_urls, session, max_workers=5, progress_bar=None):
    """Download all PDFs in parallel"""
    downloaded = {}
    errors = []
    total = len(pdf_urls)

    if total == 0:
        return downloaded, errors

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                download_single_pdf, url, session, idx
            ): (url, idx)
            for idx, url in enumerate(pdf_urls, 1)
        }

        completed = 0
        for future in as_completed(future_map):
            url, idx = future_map[future]
            filename, content, success, error = future.result()

            completed += 1
            if progress_bar:
                progress_bar.progress(
                    completed / total,
                    text=f"Downloading {completed}/{total}: {filename}"
                )

            if success and content:
                original = filename
                counter = 1
                while filename in downloaded:
                    name, ext = os.path.splitext(original)
                    filename = f"{name}_{counter}{ext}"
                    counter += 1
                downloaded[filename] = content
            else:
                errors.append({
                    'url': url,
                    'filename': filename,
                    'error': error
                })

    return downloaded, errors


def create_zip(files_dict):
    """Create ZIP in memory"""
    buf = BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files_dict.items():
            zf.writestr(fname, content)
    buf.seek(0)
    return buf


def generate_report(page_url, pdf_links, downloaded, errors, 
                    network_log=None, json_responses=None):
    """Generate detailed TXT report"""
    lines = []
    lines.append("=" * 70)
    lines.append("SMART PDF DOWNLOAD REPORT")
    lines.append("=" * 70)
    lines.append(f"Source Page  : {page_url}")
    lines.append(f"Scan Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"PDFs Found  : {len(pdf_links)}")
    lines.append(f"Downloaded  : {len(downloaded)}")
    lines.append(f"Failed      : {len(errors)}")
    lines.append("=" * 70)
    lines.append("")

    lines.append("─── ALL PDF LINKS FOUND ───")
    for i, link in enumerate(sorted(pdf_links), 1):
        lines.append(f"  {i:3d}. {link}")
    lines.append("")

    if downloaded:
        lines.append("─── SUCCESSFULLY DOWNLOADED ───")
        for fname in sorted(downloaded.keys()):
            size = len(downloaded[fname]) / 1024
            lines.append(f"  ✓ {fname} ({size:.1f} KB)")
        lines.append("")

    if errors:
        lines.append("─── FAILED DOWNLOADS ───")
        for err in errors:
            lines.append(f"  ✗ {err['url']}")
            lines.append(f"    Error: {err['error']}")
        lines.append("")

    if json_responses:
        lines.append("─── JSON API ENDPOINTS DETECTED ───")
        for resp in json_responses:
            lines.append(f"  → {resp['url']}")
            lines.append(f"    Preview: {resp['data_preview'][:200]}")
        lines.append("")

    if network_log:
        lines.append(f"─── NETWORK REQUESTS CAPTURED: {len(network_log)} ───")
        for req in network_log[:50]:
            lines.append(
                f"  [{req['status']}] {req['type'][:30]:30s} {req['url'][:80]}"
            )
        lines.append("")

    lines.append("=" * 70)
    lines.append("END OF REPORT")
    return "\n".join(lines)


# ─────────────────────────────────────────────
# STREAMLIT UI
# ─────────────────────────────────────────────

st.title("📥 Smart PDF Downloader")
st.markdown(
    "**Automatically intercepts Network tab requests** to find "
    "PDFs hidden behind JavaScript/API calls"
)

tab1, tab2, tab3 = st.tabs([
    "🔍 Smart Scan (Network Intercept)",
    "📄 HTML-Only Scan (Fast)",
    "📋 Paste URLs Directly"
])

# ════════════════════════════════════════════
# TAB 1: SMART SCAN WITH NETWORK INTERCEPT
# ════════════════════════════════════════════
with tab1:
    st.header("🔍 Smart Scan — Intercepts Network Requests")
    st.markdown("""
    This mode:
    1. Opens the page in a headless browser
    2. **Monitors ALL network requests** (like Network tab in DevTools)
    3. **Clicks on tabs/buttons** to trigger lazy-loaded content
    4. **Parses JSON responses** to extract hidden PDF URLs
    5. Collects everything and downloads in bulk
    """)

    page_url = st.text_input(
        "Webpage URL",
        placeholder="https://www.shriramfinance.in/investors/investor-information",
        key="smart_url"
    )

    col1, col2, col3 = st.columns(3)
    with col1:
        wait_time = st.slider(
            "Wait time (seconds)", 5, 30, 10,
            help="How long to wait for page to fully load"
        )
    with col2:
        click_tabs_option = st.checkbox(
            "Click tabs/buttons automatically", value=True,
            help="Clicks visible tabs to trigger more API calls"
        )
    with col3:
        max_workers = st.slider(
            "Parallel downloads", 1, 10, 5,
            key="smart_workers"
        )

    if st.button("🚀 Smart Scan & Find PDFs", key="smart_scan", type="primary"):
        if not page_url.strip():
            st.error("Please enter a URL!")
        else:
            # Install playwright if needed
            with st.spinner("Setting up browser engine (first time only)..."):
                pw_installed = install_playwright()

            if not pw_installed:
                st.error(
                    "Could not install Playwright. "
                    "Try HTML-Only Scan (Tab 2) or paste URLs (Tab 3)."
                )
            else:
                all_pdfs = set()

                # Phase 1: HTML scan
                with st.spinner("Phase 1: Scanning HTML source..."):
                    session = get_session()
                    html_pdfs = extract_pdfs_from_html(
                        page_url.strip(), session
                    )
                    all_pdfs.update(html_pdfs)
                    st.info(f"HTML scan found: {len(html_pdfs)} PDF links")

                # Phase 2: Network intercept
                with st.spinner(
                    "Phase 2: Intercepting network requests "
                    "(this takes ~30 seconds)..."
                ):
                    network_pdfs, net_log, json_resps = \
                        intercept_network_for_pdfs(
                            page_url.strip(),
                            wait_time=wait_time,
                            click_tabs=click_tabs_option
                        )
                    all_pdfs.update(network_pdfs)

                    st.session_state.network_logs = net_log
                    st.session_state.json_responses = json_resps

                    st.info(
                        f"Network intercept found: {len(network_pdfs)} "
                        f"PDF links from {len(net_log)} network requests"
                    )

                # Store results
                st.session_state.found_pdfs = sorted(list(all_pdfs))
                st.session_state.scan_done = True

                if all_pdfs:
                    st.success(
                        f"✅ Total unique PDFs found: **{len(all_pdfs)}**"
                    )
                else:
                    st.warning("No PDFs found. Check the Network Debug below.")

    # ── Show results ──
    if st.session_state.scan_done and st.session_state.found_pdfs:

        st.markdown("---")
        st.header(f"📄 Found {len(st.session_state.found_pdfs)} PDFs")

        with st.expander("View all PDF links", expanded=True):
            for i, link in enumerate(st.session_state.found_pdfs, 1):
                fname = os.path.basename(urlparse(link).path) or "unknown.pdf"
                st.text(f"{i:3d}. {fname}")
                st.caption(f"     {link}")

        # Quick TXT download
        txt_links = "\n".join(st.session_state.found_pdfs)
        st.download_button(
            label="📝 Download PDF Links as .TXT",
            data=txt_links,
            file_name=f"pdf_links_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )

        # Download all
        if st.button(
            f"⬇️ Download All {len(st.session_state.found_pdfs)} PDFs",
            key="smart_download",
            type="primary"
        ):
            session = get_session()
            progress = st.progress(0, text="Starting downloads...")

            downloaded, errors = download_all_pdfs(
                st.session_state.found_pdfs,
                session,
                max_workers=max_workers,
                progress_bar=progress
            )
            progress.progress(1.0, text="Complete!")

            st.session_state.downloaded_pdfs = downloaded

            report = generate_report(
                page_url,
                st.session_state.found_pdfs,
                downloaded,
                errors,
                st.session_state.network_logs,
                st.session_state.json_responses
            )
            st.session_state.txt_output = report

            c1, c2 = st.columns(2)
            with c1:
                st.metric("✅ Downloaded", len(downloaded))
            with c2:
                st.metric("❌ Failed", len(errors))

            if errors:
                with st.expander("Show errors"):
                    for err in errors:
                        st.text(f"✗ {err['url']}: {err['error']}")

            st.markdown("---")
            st.header("📦 Get Your Files")

            d1, d2 = st.columns(2)
            with d1:
                if downloaded:
                    zip_data = create_zip(downloaded)
                    st.download_button(
                        label=f"📦 Download ZIP ({len(downloaded)} PDFs)",
                        data=zip_data,
                        file_name=f"pdfs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                        mime="application/zip",
                        type="primary"
                    )
            with d2:
                st.download_button(
                    label="📝 Download Full Report (.TXT)",
                    data=report,
                    file_name=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain"
                )

    # ── Network Debug Section ──
    if st.session_state.network_logs:
        with st.expander(
            f"🔧 Network Debug — {len(st.session_state.network_logs)} requests captured"
        ):
            # Filter options
            filter_type = st.selectbox(
                "Filter by type:",
                ["All", "JSON only", "PDF only", "HTML only"]
            )

            for req in st.session_state.network_logs:
                show = False
                if filter_type == "All":
                    show = True
                elif filter_type == "JSON only" and 'json' in req['type']:
                    show = True
                elif filter_type == "PDF only" and (
                    'pdf' in req['type'] or '.pdf' in req['url']
                ):
                    show = True
                elif filter_type == "HTML only" and 'html' in req['type']:
                    show = True

                if show:
                    status_icon = "✅" if req['status'] == 200 else "⚠️"
                    st.text(
                        f"{status_icon} [{req['status']}] "
                        f"{req['type'][:25]:25s} | {req['url'][:100]}"
                    )

    if st.session_state.json_responses:
        with st.expander(
            f"📡 JSON APIs detected: {len(st.session_state.json_responses)}"
        ):
            for resp in st.session_state.json_responses:
                st.text(f"→ {resp['url']}")
                st.code(resp['data_preview'][:300], language="json")


# ════════════════════════════════════════════
# TAB 2: HTML ONLY SCAN (FAST, NO BROWSER)
# ════════════════════════════════════════════
with tab2:
    st.header("📄 HTML-Only Scan (Fast)")
    st.markdown(
        "Quick scan of page HTML. Works for sites with "
        "direct PDF links. Won't catch JavaScript-loaded content."
    )

    html_url = st.text_input(
        "Webpage URL",
        placeholder="https://example.com/downloads",
        key="html_url"
    )

    html_workers = st.slider("Parallel downloads", 1, 10, 5, key="html_workers")

    if st.button("🔍 Scan HTML", key="html_scan"):
        if not html_url.strip():
            st.error("Enter a URL!")
        else:
            with st.spinner("Scanning..."):
                session = get_session()
                found = extract_pdfs_from_html(html_url.strip(), session)

            if found:
                st.success(f"Found {len(found)} PDFs")
                found_list = sorted(list(found))

                for i, link in enumerate(found_list, 1):
                    st.text(f"{i}. {link}")

                txt_data = "\n".join(found_list)
                st.download_button(
                    "📝 Download links as TXT",
                    data=txt_data,
                    file_name="pdf_links.txt",
                    mime="text/plain"
                )

                if st.button("⬇️ Download All", key="html_dl"):
                    progress = st.progress(0)
                    downloaded, errors = download_all_pdfs(
                        found_list, session,
                        max_workers=html_workers,
                        progress_bar=progress
                    )

                    if downloaded:
                        zip_data = create_zip(downloaded)
                        st.download_button(
                            f"📦 ZIP ({len(downloaded)} files)",
                            data=zip_data,
                            file_name="pdfs.zip",
                            mime="application/zip"
                        )
            else:
                st.warning(
                    "No PDFs found in HTML. "
                    "Try Smart Scan (Tab 1) for JavaScript-heavy sites."
                )


# ════════════════════════════════════════════
# TAB 3: PASTE URLs DIRECTLY
# ════════════════════════════════════════════
with tab3:
    st.header("📋 Paste PDF URLs Directly")

    direct_urls = st.text_area(
        "PDF URLs (one per line)",
        height=250,
        placeholder=(
            "https://example.com/report1.pdf\n"
            "https://example.com/report2.pdf"
        )
    )

    direct_workers = st.slider(
        "Parallel downloads", 1, 10, 5, key="direct_workers"
    )

    if st.button("⬇️ Download All", key="direct_dl", type="primary"):
        urls = [
            u.strip() for u in direct_urls.strip().split('\n')
            if u.strip()
        ]

        if not urls:
            st.error("Paste at least one URL!")
        else:
            session = get_session()
            progress = st.progress(0)
            downloaded, errors = download_all_pdfs(
                urls, session,
                max_workers=direct_workers,
                progress_bar=progress
            )
            progress.progress(1.0, text="Done!")

            report = generate_report("Direct input", urls, downloaded, errors)

            st.success(f"Downloaded {len(downloaded)} of {len(urls)}")

            d1, d2 = st.columns(2)
            with d1:
                if downloaded:
                    zip_data = create_zip(downloaded)
                    st.download_button(
                        f"📦 ZIP ({len(downloaded)} files)",
                        data=zip_data,
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
    ### 🔍 Smart Scan (Recommended)
    Like having **DevTools Network tab automated**:
    1. Opens page in headless browser
    2. Captures ALL network requests
    3. Parses JSON responses for PDF URLs
    4. Clicks tabs to trigger lazy content
    5. Downloads everything in parallel

    ### 📄 HTML Scan
    - Fast but only finds static links
    - Won't catch JavaScript-loaded PDFs

    ### 📋 Direct URLs
    - Paste URLs you already have
    - Good when you've manually found links

    ---

    ### 🎯 Sites That Need Smart Scan
    - Shriram Finance
    - Sites with tabbed investor pages
    - Any page that loads PDFs via AJAX/API

    ### ⚡ Sites Where HTML Scan Works
    - Simple download pages
    - Sites with direct `<a href="file.pdf">`
    """)

    st.markdown("---")

    if st.button("🗑️ Clear Everything"):
        for key in [
            'found_pdfs', 'downloaded_pdfs', 'txt_output',
            'scan_done', 'network_logs', 'json_responses'
        ]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()
