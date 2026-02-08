# ===========================================
# :package: Malware Text Classifier (DistilBERT)
# Test Script for Local Jupyter Notebook
# ===========================================

import tensorflow as tf
from transformers import DistilBertTokenizer, TFDistilBertForSequenceClassification
import numpy as np

# --- Configuration ---
# :wrench: Replace this with the local path where your fine-tuned model is stored
MODEL_DIR = r"C:\Users\ahmed\OneDrive\Desktop\Project\AI-Proxy\Chatbot\fine-tune3"  # e.g. "C:\\Users\\Hassan\\distilbert_model"
LABELS = {0: "Benign", 1: "Malicious"}

# --- 1. Load Model and Tokenizer ---
print(f"Loading model from: {MODEL_DIR}")

try:
    tokenizer = DistilBertTokenizer.from_pretrained(MODEL_DIR)
    model = TFDistilBertForSequenceClassification.from_pretrained(MODEL_DIR)
    print(":white_check_mark: Model loaded successfully.\n")
except Exception as e:
    print(":x: Error loading model. Check the MODEL_DIR path and files.")
    raise e


# --- 2. Define Prediction Function ---
def predict_probability(prompt: str):
    """
    Runs the prompt through the model and returns the malicious probability.
    """
    # Tokenize input
    encoded_input = tokenizer(
        prompt,
        return_tensors="tf",
        truncation=True,
        padding=True,
        max_length=128
    )

    # Model prediction (logits)
    logits = model(encoded_input).logits

    # Convert logits to probabilities
    probabilities = tf.nn.softmax(logits, axis=-1).numpy()[0]

    # Probability for "Malicious" class (index 1)
    malicious_prob = probabilities[1]

    return malicious_prob
