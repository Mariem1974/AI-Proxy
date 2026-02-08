"""
Test GLiNER Model - Using Correct Local Path
Model location: ./models/gretel-gliner/models--gretelai--gretel-gliner-bi-large-v1.0/snapshots/f96d1da43b97bd1846b14a7068a57e1ab15f226e
"""

from gliner import GLiNER

print("\n" + "="*60)
print("🧪 TESTING GLINER MODEL (LOCAL)")
print("="*60 + "\n")

# Correct path to your downloaded model
MODEL_PATH = "./models/gretel-gliner/models--gretelai--gretel-gliner-bi-large-v1.0/snapshots/f96d1da43b97bd1846b14a7068a57e1ab15f226e"

print(f"📦 Loading model from local path...")
print(f"   Path: {MODEL_PATH}\n")

try:
    model = GLiNER.from_pretrained(MODEL_PATH)
    print("   ✅ Model loaded successfully!\n")
except Exception as e:
    print(f"   ❌ Error loading model: {e}\n")
    exit(1)

