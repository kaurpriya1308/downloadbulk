import streamlit as st
import os
import sys
from pathlib import Path
import tempfile
import shutil
from gtts import gTTS
import time
import urllib.request
import zipfile

st.set_page_config(
    page_title="AI Avatar Generator",
    page_icon="🎬",
    layout="wide"
)

st.markdown("# 🎬 AI Avatar Generator")
st.markdown("### Create talking avatar videos from photos + text")
st.markdown("---")

# Initialize session state
if 'audio_generated' not in st.session_state:
    st.session_state.audio_generated = False
if 'audio_path' not in st.session_state:
    st.session_state.audio_path = None

# Sidebar
with st.sidebar:
    st.markdown("## ⚙️ Settings")
    
    language = st.selectbox(
        "🌍 Language",
        ["en", "es", "fr", "de", "it", "pt", "ru", "zh-CN", "ja", "ko"],
        index=0
    )
    
    voice_speed = st.select_slider(
        "🎤 Voice Speed",
        options=["Slow", "Normal", "Fast"],
        value="Normal"
    )
    
    st.markdown("---")
    st.markdown("### 💡 Note")
    st.info("Due to Windows compatibility issues, this version generates audio only. For full video generation, please use Google Colab.")

# Main interface
col1, col2 = st.columns([1, 1])

with col1:
    st.markdown("### 📷 Upload Photo")
    uploaded_image = st.file_uploader(
        "Choose a photo (JPG, PNG)",
        type=['jpg', 'jpeg', 'png']
    )
    
    if uploaded_image:
        st.image(uploaded_image, use_column_width=True)

with col2:
    st.markdown("### 📝 Enter Text")
    text_input = st.text_area(
        "What should your avatar say?",
        height=200,
        placeholder="Example: Hello! Welcome to my channel. Today I'm going to show you something amazing..."
    )
    
    st.caption(f"Characters: {len(text_input)}")

st.markdown("---")

def generate_speech(text, lang, speed, output_path):
    """Generate speech"""
    slow = (speed == "Slow")
    tts = gTTS(text=text, lang=lang, slow=slow)
    tts.save(output_path)
    return output_path

if st.button("🎤 Generate Audio", type="primary"):
    
    if not text_input or len(text_input.strip()) < 5:
        st.error("❌ Please enter text (min 5 characters)!")
    else:
        try:
            progress = st.progress(0)
            status = st.empty()
            
            # Generate speech
            status.text("🎤 Generating speech...")
            progress.progress(50)
            
            output_dir = Path("outputs")
            output_dir.mkdir(exist_ok=True)
            
            audio_path = output_dir / f"speech_{int(time.time())}.mp3"
            generate_speech(text_input, language, voice_speed, str(audio_path))
            
            progress.progress(100)
            status.empty()
            
            st.session_state.audio_generated = True
            st.session_state.audio_path = str(audio_path)
            
            st.success("✅ Audio generated!")
            time.sleep(1)
            st.rerun()
            
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

# Show audio
if st.session_state.audio_generated and st.session_state.audio_path:
    st.markdown("---")
    st.markdown("## 🎉 Audio Ready!")
    
    audio_path = st.session_state.audio_path
    
    if os.path.exists(audio_path):
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.audio(audio_path)
        
        with col2:
            with open(audio_path, "rb") as f:
                st.download_button(
                    label="⬇️ Download Audio",
                    data=f,
                    file_name="speech.mp3",
                    mime="audio/mp3"
                )
            
            if st.button("🔄 Create Another"):
                st.session_state.audio_generated = False
                st.session_state.audio_path = None
                st.rerun()

# Google Colab section
st.markdown("---")
st.markdown("## 🚀 Want Full Video Generation?")

st.info("For complete video generation with your avatar, use Google Colab (free, works perfectly):")

with st.expander("📋 Click to see Google Colab code"):
    st.code("""
# Copy this code to Google Colab: https://colab.research.google.com/

# Setup
!git clone https://github.com/OpenTalker/SadTalker.git
%cd SadTalker
!pip install -q -r requirements.txt
!bash scripts/download_models.sh

# Upload photo
from google.colab import files
uploaded = files.upload()
photo = list(uploaded.keys())[0]

# Your text
text = "Hello! This is my AI avatar speaking."  # CHANGE THIS

# Generate speech
!pip install -q gTTS
from gtts import gTTS
tts = gTTS(text=text, lang='en')
tts.save('speech.mp3')

# Generate video
!python inference.py \\
  --driven_audio speech.mp3 \\
  --source_image {photo} \\
  --result_dir ./results \\
  --still \\
  --preprocess full

# Download
import glob
videos = glob.glob('./results/**/*.mp4', recursive=True)
if videos:
    files.download(videos[0])
    """, language="python")

st.markdown("""
### How to use Colab:
1. Go to https://colab.research.google.com/
2. Click "New Notebook"
3. Copy the code above
4. Click Run (▶️)
5. Upload your photo when prompted
6. Wait 2-3 minutes
7. Video downloads automatically!
""")

st.markdown("---")
st.markdown("<div style='text-align: center; color: #666;'><p>Made with ❤️ using Streamlit</p></div>", unsafe_allow_html=True)
