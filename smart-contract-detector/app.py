import os
import flask
from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
import tempfile
from smart_contract_detector import SmartContractVulnerabilityDetector

# Proper initialization of Flask with correct template and static folders
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# Initialize the detector
detector = SmartContractVulnerabilityDetector()

# Ensure model is loaded or trained
try:
    model_loaded = detector.load_model()
except:
    print("Training new model")
    detector.train_model()
    detector.save_model()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_contract():
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename.endswith('.sol'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            try:
                result = detector.analyze_contract(contract_file=filepath)
                # Clean up the file
                os.remove(filepath)
                return jsonify(result)
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        else:
            return jsonify({'error': 'Please upload a .sol file'}), 400
    elif 'code' in request.form:
        code = request.form['code']
        if code.strip():
            try:
                result = detector.analyze_contract(contract_code=code)
                return jsonify(result)
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        else:
            return jsonify({'error': 'Please enter Solidity code'}), 400
    else:
        return jsonify({'error': 'No file or code provided'}), 400

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    # Get port from environment variable for Render
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
