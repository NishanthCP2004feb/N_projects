"""
Test enhanced detector with newly expanded Indian domain whitelist
"""
from enhanced_benign_detector import EnhancedBenignURLDetector

print("=" * 80)
print("TESTING ENHANCED DETECTOR WITH EXPANDED WHITELIST")
print("=" * 80)

detector = EnhancedBenignURLDetector()

# Test various Indian domains
test_urls = [
    # E-commerce
    "https://www.flipkart.com/",
    "https://www.amazon.in/",
    "https://www.meesho.com/",
    
    # Fintech
    "https://www.paytm.com/",
    "https://www.phonepe.com/",
    "https://www.icicibank.com/",
    
    # Food delivery
    "https://www.zomato.com/",
    "https://www.swiggy.com/",
    
    # Travel
    "https://www.makemytrip.com/",
    "https://www.irctc.co.in/",
    
    # Government
    "https://www.india.gov.in/",
    
    # Non-Indian (should use ML model)
    "https://www.google.com/",
    
    # Suspicious
    "http://phishing-test-fake.xyz/",
]

print("\nTesting URLs:\n")
for url in test_urls:
    result = detector.predict(url)
    
    status_icon = "✅" if result['prediction'] == 'benign' else "⚠️"
    whitelist_badge = " [WHITELIST]" if result['source'] == 'Indian Trusted Domain List' else ""
    
    print(f"{status_icon} {result['prediction'].upper():<12} | {result['confidence']:>6.1%} | {url}")
    print(f"   Source: {result['source']}{whitelist_badge}")
    print()

print("=" * 80)
print("✅ Whitelist test complete!")
print(f"📊 Total protected domains: 20,484")
print("=" * 80)
