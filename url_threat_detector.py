
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import joblib
import os
import argparse

def train_and_save_model(dataset_path='url_data.csv', model_dir='saved_model'):
    """
    Trains a Logistic Regression model on a balanced and sampled dataset.
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
        print("Error: The dataset must contain 'url' and a label column ('type' or 'label').")
        return

    benign_df = data[data['type'] == 'benign']
    malicious_df = data[data['type'] != 'benign']

    # Balance the dataset
    minority_size = min(len(benign_df), len(malicious_df))
    if minority_size > 0:
        benign_df = benign_df.sample(n=minority_size, random_state=42)
        malicious_df = malicious_df.sample(n=minority_size, random_state=42)
        balanced_data = pd.concat([benign_df, malicious_df])
    else:
        balanced_data = data # Use original if one class is missing

    print("Created a balanced dataset with the following distribution:")
    print(balanced_data['type'].value_counts())

    # --- 3. Feature Engineering and Training Prep ---
    le = LabelEncoder()
    balanced_data['type_encoded'] = le.fit_transform(balanced_data['type'])
    X = balanced_data['url']
    y = balanced_data['type_encoded']

    # Use a smaller stratified sample to ensure training completes
    if len(balanced_data) > 50000:
        _, X, _, y = train_test_split(X, y, test_size=50000, random_state=42, stratify=y)
        print(f"\nUsing a stratified sample of {len(X)} for training.")


    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 5), max_features=20000)
    X_train_vectorized = vectorizer.fit_transform(X_train)
    X_test_vectorized = vectorizer.transform(X_test)

    # --- 4. Model Definition and Training ---
    print("\nDefining and training the Logistic Regression model...")
    model = LogisticRegression(random_state=42, solver='liblinear')
    model.fit(X_train_vectorized, y_train)

    # --- 5. Evaluation ---
    y_pred = model.predict(X_test_vectorized)
    class_names = le.classes_
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=class_names, zero_division=0))

    # --- 6. Save the Model ---
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)

    model_path = os.path.join(model_dir, 'url_threat_model.joblib')
    vectorizer_path = os.path.join(model_dir, 'vectorizer.joblib')
    label_encoder_path = os.path.join(model_dir, 'label_encoder.joblib')

    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    joblib.dump(le, label_encoder_path)

    print(f"\nModel and vectorizer saved to '{model_dir}'")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train a URL threat detection model.")
    parser.add_argument("--dataset", type=str, default="url_data.csv", help="Path to the dataset CSV file.")
    args = parser.parse_args()

    train_and_save_model(dataset_path=args.dataset)
