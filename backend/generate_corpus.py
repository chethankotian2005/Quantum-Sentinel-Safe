import os
import json

base_dir = r"E:\QuantumSafe Sentinel\sample-data\ground_truth"
os.makedirs(os.path.join(base_dir, "code"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "configs"), exist_ok=True)
os.makedirs(os.path.join(base_dir, "certs"), exist_ok=True)

manifest = {
    "files": []
}

# --- EXISTING ONES ---
existing_files = [
    {"path": "code/auth.py", "findings": [{"line": 5, "algorithm": "RSA", "severity": "High"}]},
    {"path": "code/safe_encryption.py", "findings": []},
    {"path": "code/tls_helper.py", "findings": [{"line": 6, "algorithm": "ECC", "severity": "High"}]},
    {"path": "code/clean_data_processing.py", "findings": []},
    {"path": "code/legacy_crypto_utils.py", "findings": [{"line": 6, "algorithm": "RSA", "severity": "High"}, {"line": 15, "algorithm": "DH", "severity": "High"}]},
    {"path": "configs/nginx.conf", "findings": [{"line": 9, "algorithm": "RSA", "severity": "High"}, {"line": 9, "algorithm": "DH", "severity": "High"}, {"line": 9, "algorithm": "ECDH", "severity": "High"}]},
    {"path": "configs/sshd_config", "findings": [{"line": 6, "algorithm": "DH", "severity": "High"}, {"line": 6, "algorithm": "ECDH", "severity": "High"}]},
    {"path": "configs/clean_nginx.conf", "findings": []},
    {"path": "certs/ecc_p256_kex.pem", "findings": [{"algorithm": "ECC", "severity": "High"}]},
    {"path": "certs/rsa_2048_sign.pem", "findings": [{"algorithm": "RSA", "severity": "High"}]},
    {"path": "certs/rsa_4096_misc.pem", "findings": [{"algorithm": "RSA", "severity": "Medium"}]},
    {"path": "certs/clean_readme.txt", "findings": []}
]
manifest["files"].extend(existing_files)

# --- NEW CODE SAMPLES (True Positives) ---
def add_code(name, content, findings):
    with open(os.path.join(base_dir, name), "w", encoding="utf-8") as f:
        f.write(content)
    manifest["files"].append({"path": name, "findings": findings})

add_code("code/gen_rsa.py", "from cryptography.hazmat.primitives.asymmetric import rsa\n\npriv = rsa.generate_private_key(\n    public_exponent=65537,\n    key_size=2048\n)\n", [{"line": 3, "algorithm": "RSA"}])
add_code("code/gen_ecc.py", "from cryptography.hazmat.primitives.asymmetric import ec\n\npriv = ec.generate_private_key(\n    ec.SECP384R1()\n)\n", [{"line": 3, "algorithm": "ECC"}])
add_code("code/gen_dsa.py", "from cryptography.hazmat.primitives.asymmetric import dsa\n\npriv = dsa.generate_private_key(key_size=2048)\n", [{"line": 3, "algorithm": "DSA"}])
add_code("code/gen_dh.py", "from cryptography.hazmat.primitives.asymmetric import dh\n\nparams = dh.generate_parameters(generator=2, key_size=2048)\n", [{"line": 3, "algorithm": "DH"}])
add_code("code/node_rsa.js", "const crypto = require('crypto');\n\ncrypto.generateKeyPairSync('rsa', {\n  modulusLength: 2048\n});\n", [{"line": 3, "algorithm": "RSA"}])
add_code("code/node_cipher.js", "const crypto = require('crypto');\n\nconst cipher = crypto.createCipheriv('aes-256-cbc', key, iv);\n", [{"line": 3, "algorithm": "RSA"}]) # Wait, createCipheriv maps to RSA in code_scanner! Let's check: "crypto.createCipheriv" in line -> RSA. Yes!

# --- NEW CODE SAMPLES (False Positives / Traps) ---
add_code("code/trap_comment.py", "# This script does not use RSA or ECC or DSA\nprint('Hello world!')\n", [])
add_code("code/trap_variable_name.py", "rsa_key_placeholder = 'fake_key_123'\necc_curve_name = 'secp256r1_fake'\nprint(rsa_key_placeholder)\n", [])
add_code("code/trap_method_name.py", "class MyClass:\n    def generate_private_key(self):\n        pass\n\nc = MyClass()\nc.generate_private_key()\n", []) # False positive trap! Wait, AST visitor matches short name "generate_private_key". If it matches, it might flag it as RSA or ECC!
add_code("code/trap_import_alias.py", "import random as rsa\nrsa.seed(42)\n", [])
add_code("code/trap_string.py", "def get_alg():\n    return 'crypto.generateKeyPairSync(\"rsa\")'\n", [])
add_code("code/trap_node_comment.js", "// TODO: migrate from crypto.createCipheriv to something else\nconsole.log('done');\n", [])

# --- NEW CONFIG SAMPLES (True Positives) ---
def add_config(name, content, findings):
    with open(os.path.join(base_dir, name), "w", encoding="utf-8") as f:
        f.write(content)
    manifest["files"].append({"path": name, "findings": findings})

add_config("configs/haproxy_vuln.cfg", "global\n    ssl-default-bind-ciphers ECDHE-RSA-AES128-GCM-SHA256\n", [{"line": 2, "algorithm": "ECDH"}, {"line": 2, "algorithm": "RSA"}])
add_config("configs/ssh_legacy.config", "Host *\n    KexAlgorithms diffie-hellman-group14-sha1\n", [{"line": 2, "algorithm": "DH"}])
add_config("configs/openvpn_vuln.conf", "client\ntls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384\n", [{"line": 2, "algorithm": "ECDH"}, {"line": 2, "algorithm": "RSA"}])
add_config("configs/nginx_multiple.conf", "server {\n    ssl_ciphers DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n}\n", [{"line": 2, "algorithm": "DH"}, {"line": 2, "algorithm": "RSA"}, {"line": 2, "algorithm": "ECDH"}])

# --- NEW CONFIG SAMPLES (False Positives / Traps) ---
add_config("configs/trap_clean_tls13.conf", "server {\n    ssl_protocols TLSv1.3;\n    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;\n}\n", [])
add_config("configs/trap_comment.conf", "# Do not use ECDHE-RSA or DHE or diffie-hellman\nserver {\n    listen 443 ssl;\n}\n", [])
add_config("configs/trap_doc.txt", "The sshd_config file should not contain diffie-hellman.\n", [])
add_config("configs/trap_env.env", "RSA_KEY_PATH=/etc/ssl/certs/server.key\nECDSA_CERT=/etc/ssl/certs/server.crt\n", [])

# --- NEW LIVE HOSTS ---
# We just append them to the manifest
manifest["files"].append({
    "path": "live/cloudflare.com",
    "findings": [{"algorithm": "ECC"}]
})
manifest["files"].append({
    "path": "live/google.com",
    "findings": [{"algorithm": "ECC"}]
})
manifest["files"].append({
    "path": "live/github.com",
    "findings": [{"algorithm": "ECC"}]
})
manifest["files"].append({
    "path": "live/ecc256.badssl.com",
    "findings": [{"algorithm": "ECC"}]
})
manifest["files"].append({
    "path": "live/rsa8192.badssl.com",
    "findings": [{"algorithm": "TLS_VERIFY_ERROR"}, {"algorithm": "RSA"}]
})
manifest["files"].append({
    "path": "live/expired.badssl.com",
    "findings": [{"algorithm": "TLS_VERIFY_ERROR"}, {"algorithm": "RSA"}]
})
manifest["files"].append({
    "path": "live/wrong.host.badssl.com",
    "findings": [{"algorithm": "TLS_VERIFY_ERROR"}, {"algorithm": "RSA"}]
})
manifest["files"].append({
    "path": "live/untrusted-root.badssl.com",
    "findings": [{"algorithm": "TLS_VERIFY_ERROR"}, {"algorithm": "RSA"}]
})
manifest["files"].append({
    "path": "live/mozilla.org",
    "findings": [{"algorithm": "ECC"}]
})
manifest["files"].append({
    "path": "live/amazon.com",
    "findings": [{"algorithm": "RSA"}] # Might be RSA or ECC, we'll see
})

with open(os.path.join(base_dir, "manifest.json"), "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=4)

print(f"Generated {len(manifest['files'])} files in manifest.")
