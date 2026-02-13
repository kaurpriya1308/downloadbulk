import streamlit as st
import requests
import json
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import base64
import pandas as pd
from io import BytesIO
import zipfile

# Page configuration
st.set_page_config(
    page_title="Bulk PDF Downloader",
    page_icon="📥",
    layout="wide"
)

# Initialize session state
if 'download_results' not in st.session_state:
    st.session_state.download_results = None
if 'downloaded_files' not in st.session_state:
    st.session_state.downloaded_files = []

class AdvancedDownloader:
    """Handle both regular URLs and JSON API endpoints"""
    
    def __init__(self, output_dir="streamlit_downloads"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def get_chrome_driver(self, headless=True):
        """Configure Chrome WebDriver"""
        chrome_options = Options()
        
        if headless:
            chrome_options.add_argument('--headless=new')
        
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        
        return driver
    
    def download_from_json_api(self, api_url, headers=None, params=None):
        """
        Download data from JSON API endpoint
        
        Args:
            api_url: API endpoint URL
            headers: Optional headers (as dict)
            params: Optional query parameters (as dict)
        """
        try:
            # Parse headers if string
            if headers and isinstance(headers, str):
                try:
                    headers = json.loads(headers)
                except:
                    # Try to parse as key:value format
                    headers_dict = {}
                    for line in headers.strip().split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers_dict[key.strip()] = value.strip()
                    headers = headers_dict
            
            # Make request
            response = requests.get(api_url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            
            # Try to parse as JSON
            try:
                data = response.json()
                return {'success': True, 'data': data, 'type': 'json'}
            except:
                # Return raw content if not JSON
                return {'success': True, 'data': response.text, 'type': 'text'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def download_page_to_pdf(self, url, filename, wait_time=5, progress_callback=None):
        """Download webpage and convert to PDF"""
        driver = None
        try:
            if progress_callback:
                progress_callback(f"Loading: {url}")
            
            driver = self.get_chrome_driver(headless=True)
            driver.get(url)
            time.sleep(wait_time)
            
            try:
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except:
                pass
            
            if not filename.endswith('.pdf'):
                filename += '.pdf'
            
            filepath = os.path.join(self.output_dir, filename)
            
            # Generate PDF
            pdf_data = driver.execute_cdp_cmd("Page.printToPDF", {
                "printBackground": True,
                "landscape": False,
                "paperWidth": 8.27,
                "paperHeight": 11.69,
                "marginTop": 0.4,
                "marginBottom": 0.4,
                "marginLeft": 0.4,
                "marginRight": 0.4,
                "displayHeaderFooter": False,
                "preferCSSPageSize": True
            })
            
            with open(filepath, 'wb') as f:
                f.write(base64.b64decode(pdf_data['data']))
            
            if progress_callback:
                progress_callback(f"✓ Saved: {filename}")
            
            return {'success': True, 'url': url, 'filepath': filepath, 'filename': filename}
            
        except Exception as e:
            return {'success': False, 'url': url, 'error': str(e)}
            
        finally:
            if driver:
                driver.quit()
    
    def save_json_to_file(self, data, filename):
        """Save JSON data to file"""
        try:
            if not filename.endswith('.json'):
                filename += '.json'
            
            filepath = os.path.join(self.output_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            return {'success': True, 'filepath': filepath, 'filename': filename}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

def create_zip_file(file_paths):
    """Create a zip file containing all downloaded files"""
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for file_path in file_paths:
            if os.path.exists(file_path):
                zip_file.write(file_path, os.path.basename(file_path))
    zip_buffer.seek(0)
    return zip_buffer

# Main Streamlit UI
st.title("📥 Advanced Bulk PDF Downloader")
st.markdown("Download web pages as PDFs or fetch data from JSON APIs found in Network tab")

# Tabs for different input methods
tab1, tab2, tab3 = st.tabs(["📄 Web Pages to PDF", "🔌 JSON API Endpoints", "📊 Upload CSV/Excel"])

# ==================== TAB 1: Web Pages ====================
with tab1:
    st.header("Convert Web Pages to PDF")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        urls_input = st.text_area(
            "Enter URLs (one per line)",
            height=200,
            placeholder="https://example.com/page1\nhttps://example.com/page2\nhttps://example.com/page3",
            help="Paste URLs from your browser. Each URL on a new line."
        )
    
    with col2:
        st.markdown("### Settings")
        wait_time = st.slider("Wait time per page (seconds)", 3, 15, 5)
        parallel = st.slider("Parallel downloads", 1, 5, 3)
        auto_filename = st.checkbox("Auto-generate filenames", value=True)
        
        if not auto_filename:
            st.info("You'll need to provide filenames in format: URL|filename.pdf")
    
    if st.button("🚀 Download All Pages", key="download_pages"):
        if not urls_input.strip():
            st.error("Please enter at least one URL!")
        else:
            # Parse URLs
            urls_dict = {}
            lines = [line.strip() for line in urls_input.split('\n') if line.strip()]
            
            for i, line in enumerate(lines, 1):
                if '|' in line and not auto_filename:
                    url, filename = line.split('|', 1)
                    urls_dict[url.strip()] = filename.strip()
                else:
                    url = line.strip()
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"page_{i:03d}_{timestamp}.pdf"
                    urls_dict[url] = filename
            
            # Download
            downloader = AdvancedDownloader()
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            results = {'successful': [], 'failed': []}
            total = len(urls_dict)
            
            with ThreadPoolExecutor(max_workers=parallel) as executor:
                futures = {
                    executor.submit(
                        downloader.download_page_to_pdf, 
                        url, 
                        filename, 
                        wait_time
                    ): (url, filename) 
                    for url, filename in urls_dict.items()
                }
                
                completed = 0
                for future in as_completed(futures):
                    result = future.result()
                    completed += 1
                    progress_bar.progress(completed / total)
                    
                    if result['success']:
                        results['successful'].append(result)
                        status_text.text(f"✓ Downloaded: {result['filename']}")
                    else:
                        results['failed'].append(result)
                        status_text.text(f"✗ Failed: {result['url']}")
            
            st.session_state.download_results = results
            st.session_state.downloaded_files = [r['filepath'] for r in results['successful']]
            
            # Show results
            st.success(f"✅ Downloaded {len(results['successful'])} of {total} pages")
            
            if results['failed']:
                st.warning(f"❌ Failed: {len(results['failed'])} pages")
                with st.expander("Show failed downloads"):
                    for item in results['failed']:
                        st.text(f"❌ {item['url']}: {item['error']}")

# ==================== TAB 2: JSON APIs ====================
with tab2:
    st.header("Fetch Data from JSON API")
    st.markdown("Perfect for API endpoints found in Network tab (F12 → Network)")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        api_url = st.text_input(
            "API Endpoint URL",
            placeholder="https://api.example.com/data",
            help="Copy the URL from Network tab in browser DevTools"
        )
        
        headers_input = st.text_area(
            "Headers (optional)",
            height=150,
            placeholder='{\n  "Authorization": "Bearer token",\n  "Content-Type": "application/json"\n}\n\nOr paste from Network tab:\nAuthorization: Bearer token\nContent-Type: application/json',
            help="Copy headers from Network tab or paste as JSON"
        )
    
    with col2:
        st.markdown("### Output Format")
        output_format = st.radio(
            "Save as:",
            ["JSON file", "View in browser", "Both"]
        )
        
        output_filename = st.text_input(
            "Output filename",
            value="api_response.json"
        )
    
    if st.button("🔌 Fetch API Data", key="fetch_api"):
        if not api_url:
            st.error("Please enter an API URL!")
        else:
            with st.spinner("Fetching data..."):
                downloader = AdvancedDownloader()
                result = downloader.download_from_json_api(api_url, headers_input)
                
                if result['success']:
                    st.success("✅ Data fetched successfully!")
                    
                    if output_format in ["JSON file", "Both"]:
                        save_result = downloader.save_json_to_file(
                            result['data'], 
                            output_filename
                        )
                        if save_result['success']:
                            st.session_state.downloaded_files.append(save_result['filepath'])
                            st.info(f"💾 Saved to: {save_result['filename']}")
                    
                    if output_format in ["View in browser", "Both"]:
                        st.markdown("### Response Data:")
                        st.json(result['data'])
                else:
                    st.error(f"❌ Error: {result['error']}")

# ==================== TAB 3: CSV/Excel Upload ====================
with tab3:
    st.header("Upload CSV/Excel File")
    st.markdown("Upload a file with columns: `url`, `filename`, `wait_time` (optional)")
    
    uploaded_file = st.file_uploader(
        "Choose a CSV or Excel file",
        type=['csv', 'xlsx', 'xls']
    )
    
    if uploaded_file:
        try:
            # Read file
            if uploaded_file.name.endswith('.csv'):
                df = pd.read_csv(uploaded_file)
            else:
                df = pd.read_excel(uploaded_file)
            
            st.markdown("### Preview:")
            st.dataframe(df.head())
            
            if st.button("🚀 Download from File", key="download_csv"):
                downloader = AdvancedDownloader()
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                results = {'successful': [], 'failed': []}
                total = len(df)
                
                for idx, row in df.iterrows():
                    url = row.get('url', '')
                    filename = row.get('filename', f'page_{idx+1}.pdf')
                    wait = int(row.get('wait_time', 5))
                    
                    if url and not url.startswith('http'):
                        continue
                    
                    status_text.text(f"Downloading: {filename}")
                    result = downloader.download_page_to_pdf(url, filename, wait)
                    
                    if result['success']:
                        results['successful'].append(result)
                        st.session_state.downloaded_files.append(result['filepath'])
                    else:
                        results['failed'].append(result)
                    
                    progress_bar.progress((idx + 1) / total)
                
                st.session_state.download_results = results
                st.success(f"✅ Downloaded {len(results['successful'])} of {total} pages")
                
        except Exception as e:
            st.error(f"Error reading file: {str(e)}")

# ==================== DOWNLOAD SECTION ====================
if st.session_state.downloaded_files:
    st.markdown("---")
    st.header("📦 Download Your Files")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"**Total Files: {len(st.session_state.downloaded_files)}**")
        
        # List files
        with st.expander("📄 Show all files"):
            for filepath in st.session_state.downloaded_files:
                st.text(f"✓ {os.path.basename(filepath)}")
    
    with col2:
        # Create zip
        if st.button("📦 Download All as ZIP"):
            zip_buffer = create_zip_file(st.session_state.downloaded_files)
            st.download_button(
                label="⬇️ Download ZIP",
                data=zip_buffer,
                file_name=f"bulk_download_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                mime="application/zip"
            )
    
    # Individual downloads
    st.markdown("### Download Individual Files")
    for filepath in st.session_state.downloaded_files[:5]:  # Show first 5
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                st.download_button(
                    label=f"⬇️ {os.path.basename(filepath)}",
                    data=f,
                    file_name=os.path.basename(filepath),
                    mime="application/pdf" if filepath.endswith('.pdf') else "application/json"
                )

# ==================== SIDEBAR ====================
with st.sidebar:
    st.header("ℹ️ How to Use")
    
    st.markdown("""
    ### 📄 Web Pages to PDF
    1. Paste URLs (one per line)
    2. Adjust settings
    3. Click "Download All Pages"
    
    ### 🔌 JSON API Endpoints
    1. Open DevTools (F12) → Network tab
    2. Find the API call
    3. Right-click → Copy → Copy URL
    4. Paste here and fetch!
    
    ### 📊 CSV Upload
    Format your CSV:
    ```
    url,filename,wait_time
    https://...,page1.pdf,5
    https://...,page2.pdf,7
    ```
    """)
    
    st.markdown("---")
    st.markdown("### 🎯 Tips")
    st.markdown("""
    - Increase wait time for slow pages
    - Use 2-3 parallel downloads
    - For APIs, copy headers from Network tab
    - Download as ZIP for bulk files
    """)
    
    if st.button("🗑️ Clear All Downloads"):
        st.session_state.downloaded_files = []
        st.session_state.download_results = None
        st.rerun()
