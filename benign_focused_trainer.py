"""
Enhanced Benign URL Detection Trainer
This script trains models with a focus on accurately detecting benign URLs
while maintaining high overall accuracy and minimizing false positives.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve
from sklearn.preprocessing import LabelEncoder
import joblib
import os
import re
from urllib.parse import urlparse
import argparse

# Common legitimate TLDs and domains
LEGITIMATE_TLDS = {
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
    '.co.uk', '.ac.uk', '.gov.uk', '.com.au', '.gov.au',
    '.ca', '.de', '.fr', '.jp', '.cn', '.in', '.br'
}

LEGITIMATE_DOMAINS = {
    'google', 'youtube', 'facebook', 'twitter', 'instagram', 'linkedin',
    'microsoft', 'apple', 'amazon', 'netflix', 'wikipedia', 'github',
    'stackoverflow', 'reddit', 'yahoo', 'bing', 'outlook', 'gmail',
    'gitlab', 'coursera', 'udemy', 'khanacademy', 'spotify', 'dropbox',
    'onedrive', 'ebay', 'walmart', 'target', 'bbc', 'nytimes', 'cnn',
    'forbes', 'techcrunch', 'medium', 'wordpress', 'blogger', 'meesho',
    'flipkart', 'snapdeal', 'myntra', 'ajio', 'paytm', 'phonepe'
}

def extract_enhanced_lexical_features(url):
    """
    Extracts comprehensive lexical features optimized for benign URL detection.
    """
    features = {}
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ''
    
    # Basic URL features
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9\./]', url))
    features['num_digits'] = sum(c.isdigit() for c in url)
    
    # Domain and subdomain features
    if hostname:
        domain_parts = hostname.split('.')
        features['num_subdomains'] = max(0, len(domain_parts) - 2)
        features['domain_length'] = len(hostname)
        features['has_www'] = 1 if hostname.startswith('www.') else 0
    else:
        features['num_subdomains'] = 0
        features['domain_length'] = 0
        features['has_www'] = 0
    
    # Suspicious keyword detection (malicious indicators)
    suspicious_keywords = [
        'login', 'verify', 'account', 'secure', 'password', 'update',
        'confirm', 'banking', 'paypal', 'signin', 'webscr', 'ebayisapi'
    ]
    features['has_suspicious_keywords'] = 1 if any(kw in url.lower() for kw in suspicious_keywords) else 0
    
    # Protocol features
    features['uses_https'] = 1 if parsed_url.scheme == 'https' else 0
    features['is_ip'] = 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname) else 0
    
    # Legitimate domain indicators (benign indicators)
    url_lower = url.lower()
    features['has_legitimate_tld'] = 1 if any(url_lower.endswith(tld) for tld in LEGITIMATE_TLDS) else 0
    features['has_known_domain'] = 1 if any(domain in hostname.lower() for domain in LEGITIMATE_DOMAINS) else 0
    
    # URL complexity and entropy features
    features['ratio_digits'] = features['num_digits'] / max(len(url), 1)
    features['ratio_special_chars'] = features['num_special_chars'] / max(len(url), 1)
    
    # Entropy of URL (measure of randomness)
    char_freq = {}
    for char in url:
        char_freq[char] = char_freq.get(char, 0) + 1
    entropy = -sum((freq / len(url)) * np.log2(freq / len(url)) for freq in char_freq.values())
    features['url_entropy'] = entropy
    
    # Path and query features
    features['path_length'] = len(parsed_url.path)
    features['has_query'] = 1 if parsed_url.query else 0
    features['query_length'] = len(parsed_url.query) if parsed_url.query else 0
    features['has_fragment'] = 1 if parsed_url.fragment else 0
    
    # Check for shortened URLs (often suspicious)
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
    features['is_shortened'] = 1 if any(short in hostname.lower() for short in shorteners) else 0
    
    # Consecutive character patterns (suspicious)
    features['has_consecutive_dots'] = 1 if '..' in url else 0
    features['has_consecutive_slashes'] = 1 if '//' in url.replace('://', '') else 0
    
    return features

def train_benign_focused_model(dataset_path='phishing_dataset_1.csv', 
                                model_dir='benign_focused_model',
                                use_all_data=False):
    """
    Trains models with enhanced focus on benign URL detection.
    """
    print("=" * 70)
    print("BENIGN-FOCUSED URL THREAT DETECTION MODEL TRAINER")
    print("=" * 70)
    
    # --- 1. Load Data ---
    try:
        data = pd.read_csv(dataset_path)
        print(f"\n✓ Loaded dataset: {dataset_path}")
        print(f"  Total samples: {len(data):,}")
    except FileNotFoundError:
        print(f"✗ Error: '{dataset_path}' not found.")
        return

    # --- 2. Preprocessing ---
    data.columns = [col.strip() for col in data.columns]
    if 'label' in data.columns:
        data = data.rename(columns={'label': 'type'})

    if 'url' not in data.columns or 'type' not in data.columns:
        print("✗ Error: Dataset must have 'url' and 'type' columns.")
        return

    print(f"\n✓ Dataset distribution:")
    print(data['type'].value_counts())

    # --- 3. Enhanced Balancing Strategy ---
    benign_df = data[data['type'] == 'benign']
    malicious_df = data[data['type'] == 'malicious']
    
    if use_all_data:
        # Use all benign data and match malicious data
        print(f"\n✓ Using ALL benign samples: {len(benign_df):,}")
        if len(malicious_df) > len(benign_df):
            malicious_df = malicious_df.sample(n=len(benign_df), random_state=42)
        balanced_data = pd.concat([benign_df, malicious_df])
    else:
        # Standard balanced approach but with larger sample
        sample_size = min(len(benign_df), len(malicious_df))
        if sample_size > 100000:
            sample_size = 100000  # Use up to 100k of each
        
        benign_df = benign_df.sample(n=sample_size, random_state=42)
        malicious_df = malicious_df.sample(n=sample_size, random_state=42)
        balanced_data = pd.concat([benign_df, malicious_df])
    
    print(f"\n✓ Balanced dataset created:")
    print(balanced_data['type'].value_counts())

    # --- 4. Feature Engineering ---
    print("\n✓ Extracting enhanced lexical features...")
    lexical_features = balanced_data['url'].apply(extract_enhanced_lexical_features)
    features_df = pd.DataFrame(lexical_features.tolist())
    
    print(f"  Extracted {len(features_df.columns)} lexical features")

    # Combine features with labels
    full_df = pd.concat([features_df.reset_index(drop=True), 
                         balanced_data['type'].reset_index(drop=True)], axis=1)

    # --- 5. Prepare Training Data ---
    le = LabelEncoder()
    full_df['type_encoded'] = le.fit_transform(full_df['type'])

    X = full_df.drop(['type', 'type_encoded'], axis=1)
    y = full_df['type_encoded']
    feature_columns = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n✓ Training set: {len(X_train):,} samples")
    print(f"✓ Test set: {len(X_test):,} samples")

    # --- 6. Train Random Forest Model (Optimized for Benign Detection) ---
    print("\n" + "=" * 70)
    print("TRAINING RANDOM FOREST MODEL")
    print("=" * 70)
    
    # Use class weights to penalize false positives on benign class
    class_weights = {
        le.transform(['benign'])[0]: 1.2,  # Slightly higher weight for benign
        le.transform(['malicious'])[0]: 1.0
    }
    
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=10,
        min_samples_leaf=5,
        class_weight=class_weights,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    
    rf_model.fit(X_train, y_train)
    
    # Evaluate Random Forest
    y_pred_rf = rf_model.predict(X_test)
    print("\n✓ Random Forest Classification Report:")
    print(classification_report(y_test, y_pred_rf, target_names=le.classes_, zero_division=0))
    
    # Show confusion matrix
    cm = confusion_matrix(y_test, y_pred_rf)
    print("\n✓ Confusion Matrix:")
    print(f"                Predicted Benign  Predicted Malicious")
    print(f"Actual Benign        {cm[0][0]:8d}         {cm[0][1]:8d}")
    print(f"Actual Malicious     {cm[1][0]:8d}         {cm[1][1]:8d}")
    
    false_positives = cm[1][0]  # Malicious predicted as benign (CRITICAL)
    false_negatives = cm[0][1]  # Benign predicted as malicious
    print(f"\n⚠ False Positives (Malicious shown as Benign): {false_positives}")
    print(f"⚠ False Negatives (Benign shown as Malicious): {false_negatives}")

    # --- 7. Train Gradient Boosting Model (Additional Layer) ---
    print("\n" + "=" * 70)
    print("TRAINING GRADIENT BOOSTING MODEL")
    print("=" * 70)
    
    gb_model = GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.1,
        max_depth=5,
        random_state=42,
        verbose=1
    )
    
    gb_model.fit(X_train, y_train)
    
    y_pred_gb = gb_model.predict(X_test)
    print("\n✓ Gradient Boosting Classification Report:")
    print(classification_report(y_test, y_pred_gb, target_names=le.classes_, zero_division=0))

    # --- 8. Feature Importance Analysis ---
    print("\n" + "=" * 70)
    print("TOP 15 MOST IMPORTANT FEATURES")
    print("=" * 70)
    
    feature_importance = pd.DataFrame({
        'feature': feature_columns,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    for idx, row in feature_importance.head(15).iterrows():
        print(f"{row['feature']:30s}: {row['importance']:.4f}")

    # --- 9. Save Models ---
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)

    rf_model_path = os.path.join(model_dir, 'benign_focused_rf_model.joblib')
    gb_model_path = os.path.join(model_dir, 'benign_focused_gb_model.joblib')
    label_encoder_path = os.path.join(model_dir, 'benign_label_encoder.joblib')
    features_path = os.path.join(model_dir, 'benign_features.joblib')

    joblib.dump(rf_model, rf_model_path)
    joblib.dump(gb_model, gb_model_path)
    joblib.dump(le, label_encoder_path)
    joblib.dump(feature_columns, features_path)

    print("\n" + "=" * 70)
    print("✓ MODELS SAVED SUCCESSFULLY")
    print("=" * 70)
    print(f"  Directory: {model_dir}")
    print(f"  - Random Forest Model")
    print(f"  - Gradient Boosting Model")
    print(f"  - Label Encoder")
    print(f"  - Feature Definitions")
    
    # --- 10. Final Recommendations ---
    print("\n" + "=" * 70)
    print("MODEL PERFORMANCE SUMMARY")
    print("=" * 70)
    
    report_dict = classification_report(y_test, y_pred_rf, output_dict=True, zero_division=0)
    
    # Access metrics using string labels from le.classes_
    benign_label = str(le.classes_[0]) if le.classes_[0] == 'benign' else str(le.classes_[1])
    
    if benign_label in report_dict:
        rf_benign_precision = report_dict[benign_label]['precision']
        rf_benign_recall = report_dict[benign_label]['recall']
    else:
        # Fallback: calculate from confusion matrix
        benign_idx = 0 if le.classes_[0] == 'benign' else 1
        rf_benign_precision = cm[benign_idx][benign_idx] / (cm[benign_idx][benign_idx] + cm[1-benign_idx][benign_idx])
        rf_benign_recall = cm[benign_idx][benign_idx] / (cm[benign_idx][benign_idx] + cm[benign_idx][1-benign_idx])
    
    print(f"\n✓ Benign URL Detection (Random Forest):")
    print(f"  - Precision: {rf_benign_precision:.4f} (accuracy when predicting benign)")
    print(f"  - Recall: {rf_benign_recall:.4f} (% of benign URLs correctly identified)")
    print(f"\n✓ False Positive Rate: {false_positives / (cm[1][0] + cm[1][1]) * 100:.2f}%")
    print(f"  (Malicious URLs incorrectly shown as benign)")
    
    print("\n" + "=" * 70)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train benign-focused URL detection models.")
    parser.add_argument("--dataset", type=str, default="phishing_dataset_1.csv", 
                       help="Path to the dataset CSV file.")
    parser.add_argument("--all-data", action="store_true",
                       help="Use all available data instead of sampling.")
    args = parser.parse_args()

    train_benign_focused_model(dataset_path=args.dataset, use_all_data=args.all_data)
