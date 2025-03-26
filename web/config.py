# web/config.py
from flask import Flask, jsonify, request
import os

app = Flask(__name__)
running = True  # Shared with monitor (simplified for now)

@app.route('/')
def home():
    return "NetWatch Config GUI"

@app.route('/status', methods=['GET'])
def get_status():
    return jsonify({"monitoring": running})

@app.route('/toggle', methods=['POST'])
def toggle_monitoring():
    global running
    running = not running
    return jsonify({"monitoring": running, "message": "Monitoring toggled"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
