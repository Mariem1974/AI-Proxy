"""
Script to download GLiNER model from Hugging Face to local directory
"""

from gliner import GLiNER
import os

# Create directory to store the model
model_dir = "./models/gretel-gliner"
os.makedirs(model_dir, exist_ok=True)

print("Downloading GLiNER model from Hugging Face...")
print("This may take a few minutes (model size ~1.5GB)...")

try:
    # Download and cache the model
    model = GLiNER.from_pretrained(
        "gretelai/gretel-gliner-bi-large-v1.0",
        cache_dir=model_dir
    )
    
    print(f"\n✅ Model downloaded successfully!")
    print(f"📁 Model location: {model_dir}")
    print(f"\nYou can now load it using:")
    print(f'model = GLiNER.from_pretrained("{model_dir}")')
    
except Exception as e:
    print(f"\n❌ Error downloading model: {e}")
    print("\nTroubleshooting:")
    print("1. Check your internet connection")
    print("2. Make sure you have enough disk space (~2GB)")
    print("3. Try running: pip install --upgrade gliner huggingface-hub")