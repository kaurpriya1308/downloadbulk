# 🎬 AI Avatar Generator - Google Colab Version

## Step-by-Step Instructions:

1. **Open Google Colab:** https://colab.research.google.com/

2. **Click:** File → New Notebook

3. **Copy and paste this COMPLETE code:**

```python
#@title 🎬 AI Avatar Generator - Click Play ▶️

#@markdown ### Enter your text:
your_text = "Hello! This is my AI avatar. You can change this text to say anything you want!" #@param {type:"string"}

#@markdown ### Settings:
language = "en" #@param ["en", "es", "fr", "de", "it", "pt"]
enhance_face = True #@param {type:"boolean"}

print("🚀 Starting setup...")
print("="*60)

# Download SadTalker
print("\n📥 Downloading SadTalker...")
!git clone https://github.com/OpenTalker/SadTalker.git 2>/dev/null || echo "Already exists"
%cd SadTalker

# Install packages
print("\n📦 Installing packages (3-5 minutes)...")
!pip install -q -r requirements.txt
!pip install -q gTTS

# Download models
print("\n⬇️ Downloading AI models (5-10 minutes, only first time)...")
import os
if not os.path.exists('checkpoints'):
    !bash scripts/download_models.sh
else:
    print("✅ Models already exist")

# Upload photo
print("\n" + "="*60)
print("📷 UPLOAD YOUR PHOTO")
print("="*60)
from google.colab import files
uploaded = files.upload()
photo = list(uploaded.keys())[0]
print(f"✅ Uploaded: {photo}")

# Generate speech
print(f"\n🎤 Generating speech ({language})...")
from gtts import gTTS
tts = gTTS(text=your_text, lang=language)
tts.save('speech.mp3')
print("✅ Speech generated")

# Generate video
print("\n🎬 Creating video (1-2 minutes)...")
enhancer = "gfpgan" if enhance_face else "none"

!python inference.py \
  --driven_audio speech.mp3 \
  --source_image {photo} \
  --result_dir ./results \
  --still \
  --preprocess full \
  --enhancer {enhancer}

# Find and download
print("\n🔍 Finding video...")
import glob
from IPython.display import Video

videos = glob.glob('./results/**/*.mp4', recursive=True)

if videos:
    video = videos[0]
    print("\n" + "="*60)
    print("✅ SUCCESS! VIDEO CREATED!")
    print("="*60)
    
    # Show preview
    Video(video, width=640)
    
    # Download
    print("\n⬇️ Downloading...")
    files.download(video)
    print("✅ Check your Downloads folder!")
else:
    print("❌ No video generated")
