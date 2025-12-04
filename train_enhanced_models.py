"""
Retrain benign-focused model with enhanced typosquatting dataset.
This ensures the ML models can also recognize typosquatting patterns.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os
import re
from urllib.parse import urlparse
import math
from collections import Counter

def extract_features(url):
    """Extract comprehensive lexical features from URL."""
    features = {}
    
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else ''
        path = parsed_url.path if parsed_url.path else ''
        netloc = parsed_url.netloc if parsed_url.netloc else ''
        
        # Length features
        features['url_length'] = len(url)
        features['hostname_length'] = len(hostname)
        features['path_length'] = len(path)
        
        # Character counting
        features['digit_count'] = sum(c.isdigit() for c in url)
        features['letter_count'] = sum(c.isalpha() for c in url)
        features['special_char_count'] = len(re.findall(r'[^a-zA-Z0-9]', url))
        
        # Domain features
        features['subdomain_count'] = hostname.count('.') - 1 if hostname.count('.') > 0 else 0
        features['dots_in_url'] = url.count('.')
        features['hyphens_in_hostname'] = hostname.count('-')
        
        # Suspicious patterns
        features['has_ip_address'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', hostname) else 0
        features['has_at_symbol'] = 1 if '@' in url else 0
        features['has_double_slash'] = 1 if '//' in url.replace('://', '') else 0
        
        # Case variation detection (NEW FEATURE)
        features['has_mixed_case'] = 1 if netloc != netloc.lower() else 0
        features['uppercase_count'] = sum(1 for c in netloc if c.isupper())
        
        # Digit substitution patterns (NEW FEATURE)
        digit_subs = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g'}
        features['has_digit_substitution'] = 1 if any(d in hostname for d in digit_subs.keys()) else 0
        
        # Character repetition (NEW FEATURE)
        max_repeat = max((len(list(g)) for k, g in __import__('itertools').groupby(hostname)), default=1)
        features['max_char_repeat'] = max_repeat
        features['has_suspicious_repeat'] = 1 if max_repeat >= 3 else 0
        
        # Entropy
        def calculate_entropy(s):
            if not s:
                return 0
            p = Counter(s)
            length = float(len(s))
            return -sum((count/length) * math.log2(count/length) for count in p.values())
        
        features['url_entropy'] = calculate_entropy(url)
        features['hostname_entropy'] = calculate_entropy(hostname)
        
        # Path features
        features['path_slashes'] = path.count('/')
        features['query_length'] = len(parsed_url.query) if parsed_url.query else 0
        
        # TLD features
        tld_match = re.search(r'\.(com|net|org|edu|gov|in|co\.in|uk|au)$', hostname)
        features['has_common_tld'] = 1 if tld_match else 0
        
    except Exception as e:
        print(f"Error extracting features from URL: {url}")
        print(f"Error: {e}")
    
    return features

def train_enhanced_model(dataset_path='phishing_dataset_enhanced.csv', output_dir='benign_focused_model'):
    """Train Random Forest and Gradient Boosting models on enhanced dataset."""
    
    print("=" * 70)
    print("Training Enhanced Benign-Focused Models with Typosquatting Detection")
    print("=" * 70)
    
    # Load data
    print("\n[1] Loading dataset...")
    df = pd.read_csv(dataset_path)
    print(f"    Loaded {len(df)} URLs")
    print(f"    Label distribution:")
    print(df['label'].value_counts())
    
    # Normalize labels (convert 'malicious' to 'phishing')
    df['label'] = df['label'].replace('malicious', 'phishing')
    
    # Balance the dataset
    print("\n[2] Balancing dataset...")
    benign_df = df[df['label'] == 'benign']
    phishing_df = df[df['label'] == 'phishing']
    
    # Use equal samples from each class
    min_samples = min(len(benign_df), len(phishing_df), 100000)  # Limit to 100k each for training speed
    benign_df = benign_df.sample(n=min_samples, random_state=42)
    phishing_df = phishing_df.sample(n=min_samples, random_state=42)
    
    balanced_df = pd.concat([benign_df, phishing_df], ignore_index=True)
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"    Balanced dataset size: {len(balanced_df)}")
    print(f"    Benign: {len(benign_df)}, Phishing: {len(phishing_df)}")
    
    # Extract features
    print("\n[3] Extracting features...")
    features_list = []
    for idx, url in enumerate(balanced_df['url']):
        if idx % 10000 == 0:
            print(f"    Processed {idx}/{len(balanced_df)} URLs...")
        features_list.append(extract_features(url))
    
    features_df = pd.DataFrame(features_list)
    print(f"    Extracted {len(features_df.columns)} features")
    print(f"    Features: {list(features_df.columns)}")
    
    # Prepare for training
    print("\n[4] Preparing for training...")
    le = LabelEncoder()
    y = le.fit_transform(balanced_df['label'])
    X = features_df.values
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    print(f"    Training set: {len(X_train)}")
    print(f"    Test set: {len(X_test)}")
    
    # Train Random Forest
    print("\n[5] Training Random Forest model...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    
    rf_pred = rf_model.predict(X_test)
    print("\n    Random Forest Classification Report:")
    print(classification_report(y_test, rf_pred, target_names=le.classes_))
    
    # Train Gradient Boosting
    print("\n[6] Training Gradient Boosting model...")
    gb_model = GradientBoostingClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42
    )
    gb_model.fit(X_train, y_train)
    
    gb_pred = gb_model.predict(X_test)
    print("\n    Gradient Boosting Classification Report:")
    print(classification_report(y_test, gb_pred, target_names=le.classes_))
    
    # Test on specific typosquatting examples
    print("\n[7] Testing on typosquatting examples...")
    typosquat_tests = [
        ('https://www.youtube.com', 'benign'),
        ('https://www.youtUbe.com', 'phishing'),
        ('https://www.youTube.com', 'phishing'),
        ('https://www.g00gle.com', 'phishing'),
        ('https://www.google.com', 'benign'),
        ('https://www.gooogle.com', 'phishing'),
        ('https://www.faceb00k.com', 'phishing'),
    ]
    
    print("\n    Model predictions on test cases:")
    print("    " + "-" * 60)
    for url, expected in typosquat_tests:
        test_features = extract_features(url)
        test_array = np.array([[test_features[col] for col in features_df.columns]])
        rf_prediction = le.inverse_transform([rf_model.predict(test_array)[0]])[0]
        gb_prediction = le.inverse_transform([gb_model.predict(test_array)[0]])[0]
        
        rf_status = "✓" if rf_prediction == expected else "✗"
        gb_status = "✓" if gb_prediction == expected else "✗"
        
        print(f"    {url:<35}")
        print(f"      Expected: {expected:<10} | RF: {rf_prediction:<10} {rf_status} | GB: {gb_prediction:<10} {gb_status}")
    
    # Save models
    print(f"\n[8] Saving models to '{output_dir}'...")
    os.makedirs(output_dir, exist_ok=True)
    
    joblib.dump(rf_model, os.path.join(output_dir, 'benign_focused_rf_model.joblib'))
    joblib.dump(gb_model, os.path.join(output_dir, 'benign_focused_gb_model.joblib'))
    joblib.dump(le, os.path.join(output_dir, 'benign_label_encoder.joblib'))
    joblib.dump(features_df.columns.tolist(), os.path.join(output_dir, 'benign_features.joblib'))
    
    print(f"    ✓ Models saved successfully!")
    print("\n" + "=" * 70)
    print("Training Complete!")
    print("=" * 70)
    print("\nNote: The homograph detection in enhanced_benign_detector.py will")
    print("catch case variations like 'youtUbe.com' BEFORE the ML models,")
    print("providing 95% confidence phishing detection.")
    print("=" * 70)

if __name__ == '__main__':
    train_enhanced_model()
