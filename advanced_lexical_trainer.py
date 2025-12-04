import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import argparse
import os

def train_advanced_lexical_model(dataset_path):
    """
    Trains an advanced lexical model from the new dataset.
    """
    print("[*] Loading advanced lexical dataset...")
    df = pd.read_csv(dataset_path)

    # --- Feature Selection ---
    # Select a subset of promising features. We can refine this later.
    features = [
        'Querylength', 'domain_token_count', 'path_token_count', 'avgdomaintokenlen',
        'longdomaintokenlen', 'avgpathtokenlen', 'charcompvowels', 'charcompace',
        'ldl_url', 'ldl_domain', 'ldl_path', 'urlLen', 'domainlength', 'pathLength',
        'subDirLen', 'NumberofDotsinURL', 'CharacterContinuityRate', 'URL_DigitCount',
        'host_DigitCount', 'URL_Letter_Count', 'host_letter_count', 'SymbolCount_URL',
        'SymbolCount_Domain', 'Entropy_URL', 'Entropy_Domain', 'has_char_substitutions'
    ]

    # --- Feature Engineering ---
    def has_char_substitutions(domain):
        substitutions = {'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4'}
        for char, num in substitutions.items():
            if num in domain:
                return 1
        return 0

    # The 'domain' is not a column, so we must extract it from the 'url' column,
    # which is not present in this dataset. We will skip this feature for now.
    # In a real-world scenario, you would need a 'url' column to extract the domain from.
    features.remove('has_char_substitutions')

    # The label is in the last column
    label_col = df.columns[-1]

    X = df[features]
    y = df[label_col]
    
    # Check class distribution
    print("\n[*] Original class distribution:")
    print(y.value_counts())
    
    # Balance the dataset to prevent bias toward majority classes
    print("\n[*] Balancing the dataset...")
    from sklearn.utils import resample
    
    # Separate by class
    df_combined = pd.concat([X, y], axis=1)
    classes = y.unique()
    
    # Find the minimum class size (to downsample) or use a reasonable size
    class_sizes = [len(df_combined[df_combined[label_col] == cls]) for cls in classes]
    target_size = min(min(class_sizes), 50000)  # Cap at 50k per class
    
    balanced_dfs = []
    for cls in classes:
        df_class = df_combined[df_combined[label_col] == cls]
        if len(df_class) > target_size:
            df_class_sampled = resample(df_class, n_samples=target_size, random_state=42)
        else:
            df_class_sampled = df_class
        balanced_dfs.append(df_class_sampled)
    
    df_balanced = pd.concat(balanced_dfs)
    X = df_balanced[features]
    y = df_balanced[label_col]
    
    print("\n[*] Balanced class distribution:")
    print(y.value_counts())

    print("\n[*] Splitting data into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("\n[*] Training the Random Forest classifier with balanced class weights...")
    # Use balanced class weights to give equal importance to all classes
    model = RandomForestClassifier(
        n_estimators=200,  # Increased from 100
        max_depth=30,      # Prevent overfitting
        min_samples_split=10,
        min_samples_leaf=4,
        class_weight='balanced',  # Important: balance classes
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    model.fit(X_train, y_train)

    print("\n[*] Evaluating the model...")
    y_pred = model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))
    
    # Print per-class accuracy
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_test, y_pred)
    print("\n[*] Per-class accuracy:")
    for i, cls in enumerate(sorted(y.unique())):
        accuracy = cm[i, i] / cm[i].sum() if cm[i].sum() > 0 else 0
        print(f"  {cls}: {accuracy:.2%}")

    # --- Save the Model and Columns ---
    output_dir = 'advanced_lexical_model'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    joblib.dump(model, os.path.join(output_dir, 'advanced_lexical_model.joblib'))
    joblib.dump(features, os.path.join(output_dir, 'advanced_lexical_features.joblib'))

    print(f"\n[*] Advanced lexical model and feature list saved to '{output_dir}'")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train an advanced lexical model for URL threat detection.")
    parser.add_argument('--dataset', default='lexical_features.csv', help='Path to the lexical features dataset.')
    args = parser.parse_args()

    train_advanced_lexical_model(args.dataset)
