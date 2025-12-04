"""
Generate comprehensive typosquatting training data including case variations.
This script creates synthetic phishing URLs based on popular brands.
"""

import pandas as pd
import random
from urllib.parse import urlparse

# Popular brands to protect against typosquatting
TRUSTED_BRANDS = [
    'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com', 'paypal.com',
    'ebay.com', 'yahoo.com', 'bing.com', 'github.com', 'reddit.com',
    'wikipedia.org', 'youtube.com', 'whatsapp.com', 'gmail.com', 'outlook.com',
    # Indian brands
    'flipkart.com', 'paytm.com', 'phonepe.com', 'zomato.com',
    'swiggy.com', 'meesho.com', 'myntra.com', 'snapdeal.com', 'makemytrip.com',
    'ola.com', 'oyo.com', 'byjus.com', 'icicibank.com', 'hdfcbank.com'
]

def generate_case_variations(brand):
    """Generate case variation attacks for a brand."""
    variations = []
    domain = brand.split('.')[0]
    tld = '.' + '.'.join(brand.split('.')[1:])
    
    # Generate 5 random case variations for each brand
    for _ in range(5):
        # Randomly capitalize letters
        varied = ''.join(
            c.upper() if random.random() > 0.5 else c.lower() 
            for c in domain
        )
        # Only add if it's different from the original
        if varied != domain:
            variations.append(f"https://www.{varied}{tld}")
    
    return variations

def generate_digit_substitutions(brand):
    """Generate digit substitution attacks (e.g., g00gle.com)."""
    substitutions = {
        'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4',
        's': '5', 't': '7', 'b': '8', 'g': '9'
    }
    
    variations = []
    domain = brand.split('.')[0]
    tld = '.' + '.'.join(brand.split('.')[1:])
    
    # Try substituting each character
    for i, char in enumerate(domain):
        if char.lower() in substitutions:
            modified = domain[:i] + substitutions[char.lower()] + domain[i+1:]
            variations.append(f"https://www.{modified}{tld}")
    
    # Try multiple substitutions
    modified = domain
    for char, digit in substitutions.items():
        modified = modified.replace(char, digit)
    if modified != domain:
        variations.append(f"https://www.{modified}{tld}")
    
    return variations

def generate_character_repetition(brand):
    """Generate character repetition attacks (e.g., gooogle.com)."""
    variations = []
    domain = brand.split('.')[0]
    tld = '.' + '.'.join(brand.split('.')[1:])
    
    # Double each character once
    for i in range(len(domain)):
        if domain[i].isalpha():
            modified = domain[:i] + domain[i] * 2 + domain[i+1:]
            variations.append(f"https://www.{modified}{tld}")
    
    return variations[:5]  # Limit to 5 variations

def generate_character_omission(brand):
    """Generate character omission attacks (e.g., gogle.com)."""
    variations = []
    domain = brand.split('.')[0]
    tld = '.' + '.'.join(brand.split('.')[1:])
    
    # Remove each character once
    for i in range(len(domain)):
        modified = domain[:i] + domain[i+1:]
        if len(modified) >= 3:  # Keep domain reasonably long
            variations.append(f"https://www.{modified}{tld}")
    
    return variations[:5]  # Limit to 5 variations

def generate_typosquatting_data():
    """Generate comprehensive typosquatting training data."""
    phishing_urls = []
    benign_urls = []
    
    # Add legitimate versions of brands as benign
    for brand in TRUSTED_BRANDS:
        benign_urls.append(f"https://www.{brand}")
        benign_urls.append(f"https://{brand}")
        benign_urls.append(f"http://www.{brand}")
    
    # Generate phishing variations
    for brand in TRUSTED_BRANDS:
        print(f"Generating typosquatting variations for {brand}...")
        
        # Case variations (e.g., youtUbe.com)
        phishing_urls.extend(generate_case_variations(brand))
        
        # Digit substitutions (e.g., g00gle.com)
        phishing_urls.extend(generate_digit_substitutions(brand))
        
        # Character repetition (e.g., gooogle.com)
        phishing_urls.extend(generate_character_repetition(brand))
        
        # Character omission (e.g., gogle.com)
        phishing_urls.extend(generate_character_omission(brand))
    
    # Create DataFrame
    df_benign = pd.DataFrame({
        'url': benign_urls,
        'label': 'benign'
    })
    
    df_phishing = pd.DataFrame({
        'url': phishing_urls,
        'label': 'phishing'
    })
    
    # Combine and shuffle
    df = pd.concat([df_benign, df_phishing], ignore_index=True)
    df = df.drop_duplicates(subset=['url']).sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"\nGenerated {len(df_benign)} benign URLs")
    print(f"Generated {len(df_phishing)} phishing URLs")
    print(f"Total: {len(df)} unique URLs")
    
    return df

def merge_with_existing_dataset(new_df, existing_path='phishing_dataset_1.csv'):
    """Merge new typosquatting data with existing dataset."""
    try:
        existing_df = pd.read_csv(existing_path)
        print(f"\nLoaded existing dataset: {len(existing_df)} URLs")
        
        # Combine datasets
        combined_df = pd.concat([existing_df, new_df], ignore_index=True)
        combined_df = combined_df.drop_duplicates(subset=['url']).reset_index(drop=True)
        
        print(f"Combined dataset: {len(combined_df)} unique URLs")
        print("\nLabel distribution:")
        print(combined_df['label'].value_counts())
        
        return combined_df
    except FileNotFoundError:
        print(f"\nExisting dataset not found at '{existing_path}'. Using only new data.")
        return new_df

if __name__ == '__main__':
    print("Generating typosquatting training data...")
    print("=" * 60)
    
    # Generate new typosquatting data
    typosquatting_df = generate_typosquatting_data()
    
    # Save standalone typosquatting dataset
    typosquatting_output = 'typosquatting_training_data.csv'
    typosquatting_df.to_csv(typosquatting_output, index=False)
    print(f"\nSaved typosquatting data to: {typosquatting_output}")
    
    # Merge with existing dataset
    combined_df = merge_with_existing_dataset(typosquatting_df)
    
    # Save enhanced dataset
    enhanced_output = 'phishing_dataset_enhanced.csv'
    combined_df.to_csv(enhanced_output, index=False)
    print(f"\nSaved enhanced dataset to: {enhanced_output}")
    print(f"\n✓ Training data generation complete!")
