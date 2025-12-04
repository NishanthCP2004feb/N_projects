from flask import Flask, render_template, request, jsonify
import joblib
import os
import re
from urllib.parse import urlparse
import pandas as pd
import sys
import math
from collections import Counter
import json
from werkzeug.security import generate_password_hash, check_password_hash

# Ensure the app's directory is in the system path for module imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load enhanced detector with Indian domain support
enhanced_detector = None
try:
    from enhanced_benign_detector import EnhancedBenignURLDetector
    enhanced_detector = EnhancedBenignURLDetector()
    print("✓ Enhanced Indian domain detector loaded successfully")
except Exception as e:
    print(f"⚠ Warning: Could not load enhanced detector: {e}")

try:
    from explanation import get_explanation
except ImportError:
    # Provide a dummy function if the import fails, so the app can still run
    def get_explanation(url, prediction):
        return "explanation_module_not_found", ["Error: The 'explanation' module could not be loaded."]

app = Flask(__name__)

# Simple file-based user store for demo purposes
USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.json')

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2)

users = load_users()

# --- Load Dataset ---
url_lookup = {}
try:
    dataset_path = "phishing_dataset_1.csv"
    if os.path.exists(dataset_path):
        print("[*] Loading dataset for URL lookup...")
        df = pd.read_csv(dataset_path)
        # Create a dictionary for fast lookups: {url: label}
        url_lookup = pd.Series(df.label.values, index=df.url).to_dict()
        print(f"[*] Loaded {len(url_lookup)} URLs into the lookup table.")
    else:
        print(f"Warning: Dataset file not found at '{dataset_path}'. URL lookup will be disabled.")
except Exception as e:
    print(f"An error occurred while loading the dataset: {e}")


# --- Load Models ---
main_model, main_vectorizer, main_label_encoder = None, None, None
adv_lexical_model, adv_lexical_feature_columns = None, None

try:
    # Use relative paths for robustness
    main_model_path = "saved_model/url_threat_model.joblib"
    main_vectorizer_path = "saved_model/vectorizer.joblib"
    main_label_encoder_path = "saved_model/label_encoder.joblib"

    if os.path.exists(main_model_path):
        main_model = joblib.load(main_model_path)
        main_vectorizer = joblib.load(main_vectorizer_path)
        main_label_encoder = joblib.load(main_label_encoder_path)
    else:
        print(f"Error: Main model not found at '{main_model_path}'")

    # --- Load Advanced Lexical Model ---
    adv_lexical_model_path = "advanced_lexical_model/advanced_lexical_model.joblib"
    adv_lexical_features_path = "advanced_lexical_model/advanced_lexical_features.joblib"

    if os.path.exists(adv_lexical_model_path):
        adv_lexical_model = joblib.load(adv_lexical_model_path)
        adv_lexical_feature_columns = joblib.load(adv_lexical_features_path)
    else:
        print(f"Error: Advanced lexical model not found at '{adv_lexical_model_path}'")
        adv_lexical_model = None

except Exception as e:
    print(f"An error occurred while loading the models: {e}")

def has_char_substitutions(domain):
    """
    Checks for common character substitutions in a domain name (e.g., g00gle.com).
    """
    substitutions = {'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4'}
    for char, num in substitutions.items():
        if num in domain:
            return 1
    return 0

def extract_advanced_lexical_features(url):
    """
    Extracts a comprehensive set of lexical features from a URL.
    """
    features = {col: 0 for col in adv_lexical_feature_columns}

    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else ''
        path = parsed_url.path if parsed_url.path else ''

        # Simple length-based features
        features['Querylength'] = len(url)
        features['urlLen'] = len(url)
        features['domainlength'] = len(hostname)
        features['pathLength'] = len(path)
        features['subDirLen'] = len(path.split('/')) - 1

        # Counting features
        features['NumberofDotsinURL'] = url.count('.')
        features['URL_DigitCount'] = sum(c.isdigit() for c in url)
        features['host_DigitCount'] = sum(c.isdigit() for c in hostname)
        features['URL_Letter_Count'] = sum(c.isalpha() for c in url)
        features['host_letter_count'] = sum(c.isalpha() for c in hostname)

        # Symbol counting
        features['SymbolCount_URL'] = len(re.findall(r'[^a-zA-Z0-9]', url))
        features['SymbolCount_Domain'] = len(re.findall(r'[^a-zA-Z0-9\.]', hostname))

        # Tokenization features
        domain_tokens = hostname.split('.')
        path_tokens = [token for token in path.split('/') if token]

        features['domain_token_count'] = len(domain_tokens) if hostname else 0
        features['path_token_count'] = len(path_tokens)

        if domain_tokens and any(domain_tokens):
            features['avgdomaintokenlen'] = sum(len(t) for t in domain_tokens) / len(domain_tokens)
            features['longdomaintokenlen'] = max(len(t) for t in domain_tokens)

        if path_tokens:
            features['avgpathtokenlen'] = sum(len(t) for t in path_tokens) / len(path_tokens)

        # Character composition features
        features['charcompvowels'] = sum(1 for char in url.lower() if char in 'aeiou')
        features['charcompace'] = sum(1 for char in url.lower() if char in 'ace')

        # Longest consecutive digit sequence
        def get_ldl(s):
            digit_sequences = re.findall(r'\d+', s)
            return max(len(seq) for seq in digit_sequences) if digit_sequences else 0

        features['ldl_url'] = get_ldl(url)
        features['ldl_domain'] = get_ldl(hostname)
        features['ldl_path'] = get_ldl(path)

        # Character Continuity Rate
        alnum_count = sum(c.isalnum() for c in url)
        if len(url) > 0:
            features['CharacterContinuityRate'] = alnum_count / len(url)

        # Shannon Entropy
        def shannon_entropy(s):
            if not s: return 0
            p, lns = Counter(s), float(len(s))
            return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

        features['Entropy_URL'] = shannon_entropy(url)
        features['Entropy_Domain'] = shannon_entropy(hostname)

        # The training script removed 'has_char_substitutions', so we don't include it here
        # when creating the final DataFrame.

    except Exception as e:
        print(f"Error extracting features for URL '{url}': {e}")
        return pd.DataFrame([features], columns=adv_lexical_feature_columns)

    df = pd.DataFrame([features], columns=adv_lexical_feature_columns)
    return df

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '')

    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required.'}), 400

    if username in users:
        return jsonify({'success': False, 'error': 'Username already exists.'}), 409

    # Hash password
    users[username] = generate_password_hash(password)
    save_users(users)

    return jsonify({'success': True, 'message': 'Account created. Please login.'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '')

    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required.'}), 400

    user_hash = users.get(username)
    if not user_hash or not check_password_hash(user_hash, password):
        return jsonify({'success': False, 'error': 'Invalid credentials.'}), 401

    return jsonify({'success': True, 'message': 'Login successful.'})

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Use the enhanced detector with Indian domain whitelist
    try:
        result = enhanced_detector.predict(url)
        
        final_prediction = result['prediction']
        source = result['source']
        confidence = result.get('confidence', 0.0)
        
        # Generate explanation
        explanation_text = enhanced_detector.explain_prediction(url, result)
        explanation = [explanation_text]
        
    except Exception as e:
        return jsonify({'error': f'Prediction error: {str(e)}'}), 500

    return jsonify({
        'prediction': final_prediction,
        'explanation': explanation,
        'source': source
    })

if __name__ == '__main__':
    app.run(debug=False, port=5000)
