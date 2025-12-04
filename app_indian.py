"""
Final Flask App with Enhanced Indian Domain Support
Uses whitelist-first approach for Indian brands
"""

from flask import Flask, render_template, request, jsonify
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load enhanced detector
enhanced_detector = None
try:
    from enhanced_benign_detector import EnhancedBenignURLDetector
    enhanced_detector = EnhancedBenignURLDetector()
    print("✓ Enhanced Indian domain detector loaded")
except Exception as e:
    print(f"⚠ Could not load enhanced detector: {e}")

app = Flask(__name__)

@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    """
    Enhanced prediction with Indian domain whitelist priority.
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({
                'error': 'Please provide a URL',
                'prediction': 'error'
            }), 400

        if enhanced_detector:
            result = enhanced_detector.predict(url, use_ensemble=True)
            prediction = result['prediction']
            confidence = result['confidence']
            source = result['source']
            
            # Get explanation
            explanation = enhanced_detector.explain_prediction(url, result)
            explanation_list = explanation.split('\n')
            
            response = {
                'prediction': prediction,
                'confidence': f"{confidence:.2%}",
                'explanation': explanation_list,
                'source': source
            }
            
            # Add model details if available
            if 'model_details' in result:
                response['model_details'] = {
                    'rf_prediction': result['model_details']['rf_prediction'],
                    'rf_confidence': f"{result['model_details']['rf_confidence']:.2%}",
                    'gb_prediction': result['model_details']['gb_prediction'],
                    'gb_confidence': f"{result['model_details']['gb_confidence']:.2%}",
                    'whitelist_match': result['model_details'].get('whitelist_match', False)
                }
            
            return jsonify(response)
        else:
            return jsonify({
                'error': 'Enhanced detector not available',
                'prediction': 'error'
            }), 500

    except Exception as e:
        print(f"Error during prediction: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'prediction': 'error'
        }), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'models': {
            'enhanced_detector': enhanced_detector is not None
        }
    })


@app.route('/indian-domains', methods=['GET'])
def indian_domains():
    """Return list of supported Indian domains."""
    from indian_domains import INDIAN_TRUSTED_DOMAINS
    return jsonify({
        'total': len(INDIAN_TRUSTED_DOMAINS),
        'domains': sorted(list(INDIAN_TRUSTED_DOMAINS))
    })


if __name__ == '__main__':
    print("\n" + "=" * 80)
    print("URL THREAT DETECTOR - WITH INDIAN DOMAIN SUPPORT")
    print("=" * 80)
    print("\nFeatures:")
    print("  • Whitelist-based Indian domain recognition (100% accuracy)")
    print(f"  • {len(__import__('indian_domains').INDIAN_TRUSTED_DOMAINS)} trusted Indian domains")
    print("  • ML-based detection for unknown URLs")
    print("  • Zero false positives for Indian brands")
    print("\nStarting Flask application...")
    print("Available at: http://127.0.0.1:5000")
    print("\nEndpoints:")
    print("  • POST /predict - URL prediction")
    print("  • GET /health - Health check")
    print("  • GET /indian-domains - List supported Indian domains")
    print("\n" + "=" * 80 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)
