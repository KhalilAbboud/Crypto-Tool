from flask import Flask, request, jsonify, render_template_string
import hashlib
import base64
from cryptography.fernet import Fernet

app = Flask(__name__)

# --- helpers ---
def generate_key_from_password(password: str):
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode()).digest()
    )

# home page
@app.route("/")
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Crypto Tool (TP DATA SECURITY)</title>
    <style>
    body {
        background-color: #1e1e1e;
        color: #eaeaea;
        font-family: Arial;
    }

    .section {
        background-color: #2a2a2a;
        border: 1px solid #444;
        padding: 15px;
        margin-bottom: 15px;
        border-radius: 8px;
    }

    /* inputs */
    input {
        background-color: #333;
        color: white;
        border: 1px solid #555;
        padding: 8px;
        margin-bottom: 10px;
        width: 100%;
    }

    /* placeholder text */
    input::placeholder {
        color: #aaa;
    }

    /* result box */
    #result {
        margin-top: 15px;
        padding: 10px;
        background: #2a2a2a;
        border: 1px solid #444;
        border-radius: 6px;
        color: #00ffcc;
    }
    </style>
    </head>
    <body>
        <h2>Crypto Tool (TP DATA SECURITY)</h2>

        <div style="display:flex; gap:50px; align-items:flex-start; flex-wrap:wrap;">
    <div class="section" style="flex:1; min-width:300px;">
        <h3>Encrypt / Hash</h3>
        <input id="text" placeholder="Enter text" style="margin-bottom:10px;"><br>
        <input id="password" id="password_encrypt" placeholder="Enter password" style="margin-bottom:10px;"><br>
        <button class="btn btn-primary" onclick="encrypt()">Encrypt</button>
        <button class="btn btn-secondary" onclick="hashText()">SHA-256</button>
    </div>

    <div class="section" style="flex:1; min-width:300px;">
        <h3>Decrypt</h3>
        <input id="encrypted" placeholder="Enter encrypted text (for decrypt)" style="margin-bottom:10px;"><br>
        <input id="password" id="password_decrypt" placeholder="Enter password" style="margin-bottom:10px;"><br>
        <button class="btn btn-primary" onclick="decrypt()">Decrypt</button>
    </div>

    <div class="section" style="flex:1; min-width:300px;">
        <h3>Compare Hashes</h3>
        <input id="hash1" placeholder="Hash 1" style="margin-bottom:10px;"><br>
        <input id="hash2" placeholder="Hash 2" style="margin-bottom:10px;"><br>
        <button class="btn btn-secondary" onclick="compareHashes()">Compare</button>
    </div>
        </div>

        <h3>Result:</h3>
        <pre id="result"></pre>

        <script>
        async function encrypt() {
            const res = await fetch('/crypt', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    text: document.getElementById('text').value,
                    password: document.getElementById('password').value
                })
            });

            const data = await res.json();
            document.getElementById('result').innerText = data.encrypted || data.error;
        }

        async function hashText() {
            const res = await fetch('/hash', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    text: document.getElementById('text').value
                })
            });

            const data = await res.json();
            document.getElementById('result').innerText = data.sha256 || data.error;
        }
                                  
        async function decrypt() {
            const encrypted = document.getElementById('encrypted').value;
            const password = document.getElementById('password').value;

            const url = `/decrypt?data=${encodeURIComponent(encrypted)}&password=${encodeURIComponent(password)}`;

            const res = await fetch(url);
            const data = await res.json();

            document.getElementById('result').innerText =
                data.decrypted || data.error;
        }                

        async function compareHashes() {
            const res = await fetch('/compare', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    hash1: document.getElementById('hash1').value,
                    hash2: document.getElementById('hash2').value
                })
            });

            const data = await res.json();

            document.getElementById('result').innerText =
                data.match ? "Hashes MATCH" : "Hashes DO NOT match";
        }         
        </script>
    </body>
    </html>
    """)

# POST /crypt
@app.route("/crypt", methods=["POST"])
def crypt():
    data = request.get_json()

    text = data.get("text")
    password = data.get("password")

    if not text or not password:
        return jsonify({"error": "text and password required"}), 400

    key = generate_key_from_password(password)
    f = Fernet(key)

    encrypted = f.encrypt(text.encode()).decode()

    return jsonify({"encrypted": encrypted})


# GET /decrypt
@app.route("/decrypt", methods=["GET"])
def decrypt():
    encrypted = request.args.get("data")
    password = request.args.get("password")

    if not encrypted or not password:
        return jsonify({"error": "data and password required"}), 400

    try:
        key = generate_key_from_password(password)
        f = Fernet(key)

        decrypted = f.decrypt(encrypted.encode()).decode()

        return jsonify({"decrypted": decrypted})

    except Exception:
        return jsonify({"error": "decryption failed"}), 400


# POST /hash
@app.route("/hash", methods=["POST"])
def hash_text():
    data = request.get_json()
    text = data.get("text")

    if not text:
        return jsonify({"error": "text required"}), 400

    hash_value = hashlib.sha256(text.encode()).hexdigest()

    return jsonify({"sha256": hash_value})


if __name__ == "__main__":
    app.run(debug=True)

    @app.route("/compare", methods=["POST"])
    def compare_hashes():
        data = request.get_json()

        hash1 = data.get("hash1")
        hash2 = data.get("hash2")

        if not hash1 or not hash2:
            return jsonify({"error": "two hashes required"}), 400

        return jsonify({
            "match": hash1 == hash2
    })