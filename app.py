from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from arker import ArkerAI
from dotenv import load_dotenv
import os
import logging
import requests
import json

# Configure logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load environment variables
load_dotenv()

# Validate API keys
def validate_api_keys():
    grok_key = os.getenv("GROK_API_KEY")
    if grok_key:
        response = requests.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {grok_key}", "Content-Type": "application/json"},
            json={"model": "grok-3-latest", "messages": [{"role": "user", "content": "test"}]}
        )
        if response.status_code == 403:
            logging.warning("Grok API key valid but requires credits. Falling back to Gemini.")
            return False
        elif response.status_code != 200:
            logging.error(f"Grok API key invalid (status: {response.status_code}): {response.text}")
            return False
    return True

app = Flask(__name__, static_folder='static', static_url_path='/')
CORS(app)

# Initialize ArkerAI with all required keys
try:
    arker = ArkerAI(
        gemini_api_key=os.getenv("GEMINI_API_KEY"),
        grok_api_key=os.getenv("GROK_API_KEY"),
        openweathermap_api_key=os.getenv("OPENWEATHERMAP_API_KEY"),
        news_api_key=os.getenv("NEWS_API_KEY"),
        shodan_api_key=os.getenv("SHODAN_API_KEY")
    )
    if not validate_api_keys():
        logging.warning("Grok API key validation failed. Using Gemini as fallback.")
except Exception as e:
    logging.error(f"Error initializing Arker: {e}")
    print(f"Error initializing Arker: {e}")
    exit(1)

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/process', methods=['POST'])
def process():
    try:
        data = request.get_json()
        user_input = data.get('input', '')
        if not user_input:
            logging.warning("No command provided in /process")
            return jsonify({'error': 'No command provided'}), 400
        if user_input.lower() == 'recognize speech':
            result = arker.server_side_speech()
            logging.info(f"Server-side speech recognition: {result}")
            return jsonify({'response': result})
        response = arker.process_user_input(user_input)
        logging.info(f"Processed command: {user_input} -> {response[:100]}...")
        return jsonify({'response': response})
    except Exception as e:
        logging.error(f"Process error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/port_scan/<host>')
def port_scan(host):
    try:
        result = arker.agent_port_scan(f"port scan {host}")
        logging.info(f"Port scan for {host}: {result[:100]}...")
        return jsonify({'result': result})
    except Exception as e:
        logging.error(f"Port scan error for {host}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/crawl_website/<path:url>')
def crawl_website(url):
    try:
        result = arker.agent_crawl_website(f"crawl website {url}")
        logging.info(f"Web crawl for {url}: {result[:100]}...")
        return jsonify({'result': result})
    except Exception as e:
        logging.error(f"Web crawl error for {url}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/threat_intel/<target>')
def threat_intel(target):
    try:
        result = arker.agent_threat_intel(f"threat intel {target}")
        logging.info(f"Threat intel for {target}: {result[:100]}...")
        return jsonify({'result': result})
    except Exception as e:
        logging.error(f"Threat intel error for {target}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/dns_enum/<domain>')
def dns_enum(domain):
    try:
        result = arker.agent_subdomain_enum(f"dns enum {domain}")
        logging.info(f"DNS enum for {domain}: {result[:100]}...")
        return jsonify({'result': result})
    except Exception as e:
        logging.error(f"DNS enum error for {domain}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/news')
def news():
    try:
        result = arker.agent_get_news("news")
        logging.info(f"News fetched: {result[:100]}...")
        return jsonify({'news': result})
    except Exception as e:
        logging.error(f"News fetch error: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        logging.error(f"Flask server error: {str(e)}")
        print(f"Error starting server: {str(e)}")