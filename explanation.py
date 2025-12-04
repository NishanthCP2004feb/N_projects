import re
from urllib.parse import urlparse

def get_explanation(url, prediction):
    """
    Analyzes a URL and provides a human-readable explanation and a specific threat type.

    Args:
        url (str): The URL to analyze.
        prediction (str): The model's base prediction ('benign' or 'malicious').

    Returns:
        tuple: A tuple containing:
            - str: The specific threat type ('benign', 'phishing', 'malware', 'defacement', 'malicious').
            - list: A list of strings with reasons for the classification.
    """

    reasons = []
    # Normalize prediction to lowercase for consistency
    prediction = str(prediction).lower()
    specific_type = prediction # Start with the base prediction

    if prediction == 'benign':
        reasons.append("The URL appears to be safe based on our analysis.")
        return 'benign', reasons

    # --- Heuristics for Specific Threat Types ---
    is_phishing = False
    is_malware = False
    is_defacement = False

    # 1. Phishing Keywords (only flag if multiple indicators or in suspicious context)
    phishing_keywords = ['login', 'verify', 'account', 'update', 'secure', 'bank', 'password', 'signin']
    phishing_keyword_count = 0
    for keyword in phishing_keywords:
        if keyword in url.lower():
            reasons.append(f"URL contains a keyword commonly used in phishing: '{keyword}'.")
            phishing_keyword_count += 1
            is_phishing = True

    # 2. Malware File Extensions
    malware_extensions = ['.exe', '.zip', '.rar', '.js', '.scr', '.dll', '.bat', '.cmd', '.vbs']
    parsed_url = urlparse(url)
    path = parsed_url.path
    for ext in malware_extensions:
        if path.lower().endswith(ext):
            reasons.append(f"URL points to a file type often used to distribute malware: '{ext}'.")
            is_malware = True

    # 3. Defacement Keywords
    defacement_keywords = ['hacked', 'defaced', 'pwned', 'h4ck3d']
    for keyword in defacement_keywords:
        if keyword in url.lower():
            reasons.append(f"URL contains keywords suggesting it may be a defaced website: '{keyword}'.")
            is_defacement = True

    # --- General Malicious Heuristics (only add if prediction is already non-benign) ---
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", parsed_url.netloc):
        reasons.append("URL uses an IP address instead of a domain name, which can be suspicious.")
    if '@' in parsed_url.netloc:
        reasons.append("URL contains an '@' symbol in the domain, which can obscure the true domain.")
    if len(url) > 100:  # Increased threshold to reduce false positives
        reasons.append("URL is unusually long, a common trait of malicious URLs.")

    # --- Determine the Final Specific Type ---
    # If model already classified as specific type, prefer that unless we have strong evidence otherwise
    if prediction in ['phishing', 'malware', 'defacement', 'spam']:
        specific_type = prediction
        # Override only if we have strong contradictory evidence
        if is_malware and prediction != 'malware':
            specific_type = 'malware'
    else:
        # For generic 'malicious' prediction, use heuristics to determine specific type
        if is_phishing:
            specific_type = 'phishing'
        elif is_malware:
            specific_type = 'malware'
        elif is_defacement:
            specific_type = 'defacement'
        else:
            specific_type = 'malicious'

    # --- Default message if no specific reason is found ---
    if not reasons:
        reasons.append("This URL has characteristics associated with potentially harmful websites.")

    return specific_type, reasons

if __name__ == '__main__':
    # Example Usage
    test_url_1 = "http://bad-phishing-site.com/login"
    p_type, p_reasons = get_explanation(test_url_1, 'malicious')
    print(f"URL: '{test_url_1}' -> Type: {p_type}, Reasons: {p_reasons}")

    test_url_2 = "http://123.45.67.89/malware.exe"
    m_type, m_reasons = get_explanation(test_url_2, 'malicious')
    print(f"URL: '{test_url_2}' -> Type: {m_type}, Reasons: {m_reasons}")

    test_url_3 = "http://example-hacked-by-anonymous.com/defaced.html"
    d_type, d_reasons = get_explanation(test_url_3, 'malicious')
    print(f"URL: '{test_url_3}' -> Type: {d_type}, Reasons: {d_reasons}")
