import os
import time
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# 配置
MASTER_KEY = os.urandom(32)  # 随机生成主密钥（生产环境应安全存储）
DECRYPTED_FILES = set()      # 记录已解密的文件（生产环境用数据库）

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    """生成加密文件"""
    file_id = request.json.get('file_id')
    plaintext = request.json.get('data').encode('utf-8')
    
    # 派生动态密钥
    timestamp = int(time.time())
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=str(timestamp).encode(),
        info=file_id.encode(),
    )
    key = hkdf.derive(MASTER_KEY)
    
    # 加密数据
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # 返回加密结果（生产环境应存储密文）
    return jsonify({
        'file_id': file_id,
        'ciphertext': ciphertext.hex(),
        'nonce': nonce.hex(),
        'timestamp': timestamp
    })

@app.route('/get_key/<file_id>', methods=['GET'])
def get_decrypt_key(file_id):
    """获取解密密钥（单次有效）"""
    if file_id in DECRYPTED_FILES:
        return jsonify({'error': 'File already decrypted'}), 403
    
    # 重新派生密钥（需客户端提供时间戳）
    timestamp = request.args.get('timestamp', type=int)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=str(timestamp).encode(),
        info=file_id.encode(),
    )
    key = hkdf.derive(MASTER_KEY)
    
    DECRYPTED_FILES.add(file_id)  # 标记为已解密
    return jsonify({'key': key.hex()})

if __name__ == '__main__':
    app.run(port=5000)