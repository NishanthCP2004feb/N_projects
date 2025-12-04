"""
Comprehensive test showing meesho.com and other Indian sites are now benign.
"""

from benign_url_detector import BenignURLDetector

print("=" * 80)
print("COMPREHENSIVE TEST - INDIAN E-COMMERCE SITES")
print("=" * 80)

detector = BenignURLDetector()

# Test URLs
test_urls = {
    "Indian E-commerce": [
        "https://www.meesho.com/",
        "https://www.flipkart.com/",
        "https://www.myntra.com/",
        "https://www.snapdeal.com/",
        "https://www.ajio.com/",
    ],
    "Payment Platforms": [
        "https://paytm.com/",
        "https://phonepe.com/",
    ],
    "International (Should be Benign)": [
        "https://www.amazon.com/",
        "https://www.amazon.in/",
        "https://www.google.com/",
    ],
    "Malicious (Should be Detected)": [
        "http://phishing-login-verify.xyz/account",
        "http://192.168.1.1/admin",
    ]
}

results = {"benign": 0, "malicious": 0}

for category, urls in test_urls.items():
    print(f"\n{'=' * 80}")
    print(f"{category.upper()}")
    print(f"{'=' * 80}")
    
    for url in urls:
        result = detector.predict(url, use_ensemble=True)
        prediction = result['prediction']
        confidence = result['confidence']
        
        # Status indicator
        if "Malicious" in category:
            status = "✓ PASS" if prediction == "malicious" else "✗ FAIL"
        else:
            status = "✓ PASS" if prediction == "benign" else "✗ FAIL"
        
        results[prediction] = results.get(prediction, 0) + 1
        
        print(f"\n{status}: {url}")
        print(f"  Prediction: {prediction.upper()}")
        print(f"  Confidence: {confidence:.2%}")
        print(f"  RF: {result['model_details']['rf_prediction']} ({result['model_details']['rf_confidence']:.2%})")
        print(f"  GB: {result['model_details']['gb_prediction']} ({result['model_details']['gb_confidence']:.2%})")

print(f"\n{'=' * 80}")
print("SUMMARY")
print(f"{'=' * 80}")
print(f"Total URLs Tested: {sum(len(urls) for urls in test_urls.values())}")
print(f"Detected as Benign: {results.get('benign', 0)}")
print(f"Detected as Malicious: {results.get('malicious', 0)}")

# Calculate accuracy for Indian sites
indian_sites = len(test_urls["Indian E-commerce"]) + len(test_urls["Payment Platforms"])
print(f"\n✓ Indian E-commerce/Payment Sites: {indian_sites} tested")
print(f"✓ Expected: All should be BENIGN")
print(f"✓ Result: Verify above that all Indian sites show ✓ PASS")

print(f"\n{'=' * 80}")
print("MEESHO.COM FIX VERIFICATION")
print(f"{'=' * 80}")

meesho_result = detector.predict("https://www.meesho.com/", use_ensemble=True)
if meesho_result['prediction'] == 'benign':
    print("✅ SUCCESS: Meesho.com correctly detected as BENIGN")
    print(f"   Confidence: {meesho_result['confidence']:.2%}")
    print("   ✓ FIX VERIFIED AND WORKING!")
else:
    print("❌ FAILED: Meesho.com still detected as malicious")
    print("   ⚠ Please check the configuration")

print(f"\n{'=' * 80}\n")
