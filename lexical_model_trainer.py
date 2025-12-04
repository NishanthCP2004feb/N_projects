
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib
import os
import re
from urllib.parse import urlparse
import argparse

def extract_lexical_features(url):
    """
    Extracts a set of lexical features from a single URL.
    """
    features = {}
    parsed_url = urlparse(url)

    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9\./]', url))
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_subdomains'] = len(parsed_url.hostname.split('.')) - 2 if parsed_url.hostname else 0
    features['has_suspicious_keywords'] = 1 if any(keyword in url.lower() for keyword in ['login', 'verify', 'account', 'secure', 'password']) else 0
    features['uses_https'] = 1 if parsed_url.scheme == 'https' else 0
    features['is_ip'] = 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", parsed_url.netloc) else 0

    return features

def train_lexical_model(dataset_path='phishing_dataset_1.csv', model_dir='lexical_model'):
    """
    Trains a Random Forest model on lexical features extracted from URLs.
    """
    # --- 1. Load Data ---
    try:
        data = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"Error: '{dataset_path}' not found.")
        return

    # --- 2. Preprocessing and Balancing ---
    data.columns = [col.strip() for col in data.columns]
    if 'label' in data.columns:
        data = data.rename(columns={'label': 'type'})

    if 'url' not in data.columns or 'type' not in data.columns:
        print("Error: Dataset must have 'url' and 'type' columns.")
        return

    benign_df = data[data['type'] == 'benign']
    malicious_df = data[data['type'] != 'benign']

    minority_size = min(len(benign_df), len(malicious_df))
    if minority_size > 0:
        benign_df = benign_df.sample(n=minority_size, random_state=42)
        malicious_df = malicious_df.sample(n=minority_size, random_state=42)
        balanced_data = pd.concat([benign_df, malicious_df])
    else:
        balanced_data = data

    if len(balanced_data) > 50000:
        _, balanced_data = train_test_split(balanced_data, test_size=50000, random_state=42, stratify=balanced_data['type'])
        print(f"\nUsing a stratified sample of {len(balanced_data)} for training.")

    print("Extracting lexical features from dataset...")
    lexical_features = balanced_data['url'].apply(extract_lexical_features)
    features_df = pd.DataFrame(lexical_features.tolist())

    # Combine features with labels
    full_df = pd.concat([features_df.reset_index(drop=True), balanced_data['type'].reset_index(drop=True)], axis=1)

    # --- 3. Training Prep ---
    le = LabelEncoder()
    full_df['type_encoded'] = le.fit_transform(full_df['type'])

    X = full_df.drop(['type', 'type_encoded'], axis=1)
    y = full_df['type_encoded']

    feature_columns = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    # --- 4. Model Training ---
    print("Training the Random Forest lexical model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    # --- 5. Evaluation ---
    y_pred = model.predict(X_test)
    class_names = le.classes_
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=class_names, zero_division=0))

    # --- 6. Save the Model ---
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)

    model_path = os.path.join(model_dir, 'lexical_model.joblib')
    label_encoder_path = os.path.join(model_dir, 'lexical_label_encoder.joblib')
    features_path = os.path.join(model_dir, 'lexical_features.joblib')

    joblib.dump(model, model_path)
    joblib.dump(le, label_encoder_path)
    joblib.dump(feature_columns, features_path)

    print(f"\nLexical model and supporting files saved to '{model_dir}'")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train a lexical URL threat detection model.")
    parser.add_argument("--dataset", type=str, default="phishing_dataset_1.csv", help="Path to the dataset CSV file.")
    args = parser.parse_args()

    train_lexical_model(dataset_path=args.dataset)
