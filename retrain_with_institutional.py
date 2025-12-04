"""
Retrain the model with institutional domain support
Combines existing training data with new academic/government domains
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os
from enhanced_benign_detector import EnhancedBenignURLDetector

def load_and_combine_datasets():
    """Load all training datasets and combine them"""
    print("=" * 80)
    print("LOADING TRAINING DATASETS")
    print("=" * 80)
    
    datasets = []
    
    # Load institutional dataset
    if os.path.exists('institutional_training_data.csv'):
        inst_df = pd.read_csv('institutional_training_data.csv')
        print(f"✓ Loaded {len(inst_df)} institutional URLs")
        datasets.append(inst_df[['url', 'label']])
    
    # Load existing phishing dataset
    if os.path.exists('phishing_dataset_1.csv'):
        existing_df = pd.read_csv('phishing_dataset_1.csv')
        print(f"✓ Loaded {len(existing_df)} URLs from phishing_dataset_1.csv")
        datasets.append(existing_df[['url', 'label']])
    
    # Combine all datasets
    if datasets:
        combined_df = pd.concat(datasets, ignore_index=True)
        print(f"\n✅ Total combined dataset: {len(combined_df)} URLs")
        
        # Show distribution
        print("\nLabel Distribution:")
        print(combined_df['label'].value_counts())
        
        return combined_df
    else:
        raise FileNotFoundError("No training datasets found!")

def retrain_model():
    """Retrain the benign-focused model with institutional data"""
    print("\n" + "=" * 80)
    print("RETRAINING MODEL WITH INSTITUTIONAL SUPPORT")
    print("=" * 80)
    
    # Load datasets
    df = load_and_combine_datasets()
    
    # Initialize detector for feature extraction
    detector = EnhancedBenignURLDetector('benign_focused_model')
    
    # Extract features
    print("\n✓ Extracting features from URLs...")
    X = []
    y = []
    
    for idx, row in df.iterrows():
        if idx % 500 == 0:
            print(f"  Processed {idx}/{len(df)} URLs...")
        
        try:
            features = detector.extract_features(row['url'])
            feature_values = [features[key] for key in sorted(features.keys())]
            X.append(feature_values)
            y.append(row['label'])
        except Exception as e:
            print(f"  Warning: Error processing {row['url']}: {e}")
            continue
    
    X = np.array(X)
    y = np.array(y)
    
    print(f"\n✅ Extracted features for {len(X)} URLs")
    print(f"   Feature vector size: {X.shape[1]}")
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    print(f"\n✓ Label encoding complete")
    print(f"   Classes: {label_encoder.classes_}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    print(f"\n✓ Data split: {len(X_train)} train, {len(X_test)} test")
    
    # Train Random Forest
    print("\n✓ Training Random Forest model...")
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight={0: 1.2, 1: 1.0, 2: 1.0, 3: 1.0},  # Boost benign class
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    
    # Train Gradient Boosting
    print("✓ Training Gradient Boosting model...")
    gb_model = GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.1,
        max_depth=5,
        random_state=42
    )
    gb_model.fit(X_train, y_train)
    
    # Evaluate
    print("\n" + "=" * 80)
    print("MODEL EVALUATION")
    print("=" * 80)
    
    # Random Forest evaluation
    rf_pred = rf_model.predict(X_test)
    rf_accuracy = accuracy_score(y_test, rf_pred)
    
    print("\n📊 Random Forest Results:")
    print(f"   Accuracy: {rf_accuracy*100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, rf_pred, target_names=label_encoder.classes_, zero_division=0))
    
    # Gradient Boosting evaluation
    gb_pred = gb_model.predict(X_test)
    gb_accuracy = accuracy_score(y_test, gb_pred)
    
    print("\n📊 Gradient Boosting Results:")
    print(f"   Accuracy: {gb_accuracy*100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, gb_pred, target_names=label_encoder.classes_, zero_division=0))
    
    # Save models
    print("\n" + "=" * 80)
    print("SAVING MODELS")
    print("=" * 80)
    
    model_dir = 'benign_focused_model'
    os.makedirs(model_dir, exist_ok=True)
    
    # Save models and encoders
    joblib.dump(rf_model, os.path.join(model_dir, 'benign_focused_rf_model.joblib'))
    joblib.dump(gb_model, os.path.join(model_dir, 'benign_focused_gb_model.joblib'))
    joblib.dump(label_encoder, os.path.join(model_dir, 'benign_label_encoder.joblib'))
    
    # Save feature names
    sample_features = detector.extract_features(df.iloc[0]['url'])
    feature_names = sorted(sample_features.keys())
    joblib.dump(feature_names, os.path.join(model_dir, 'benign_features.joblib'))
    
    print(f"✅ Random Forest model saved")
    print(f"✅ Gradient Boosting model saved")
    print(f"✅ Label encoder saved")
    print(f"✅ Feature names saved ({len(feature_names)} features)")
    
    # Test on institutional URLs
    print("\n" + "=" * 80)
    print("TESTING ON INSTITUTIONAL URLS")
    print("=" * 80)
    
    test_urls = [
        'https://www.ksit.ac.in/',
        'https://www.ksit.ACC.in/',
        'https://iitb.ac.in/',
        'https://mit.edu/',
        'https://www.gov.in/',
        'https://www.uidai.gov.in/',
        'https://www.google.com/',
        'https://www.g00gle.com/',
    ]
    
    # Reload detector with new models
    detector_new = EnhancedBenignURLDetector('benign_focused_model')
    
    for url in test_urls:
        result = detector_new.predict(url)
        print(f"\n{url}")
        print(f"  → {result['prediction'].upper()} ({result['confidence']*100:.0f}% confidence)")
        print(f"  → Source: {result['source']}")
    
    print("\n" + "=" * 80)
    print("✅ RETRAINING COMPLETE!")
    print("=" * 80)

if __name__ == "__main__":
    retrain_model()
