import requests
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_URL = 'http://localhost:5000'

def demo_flow():
    # 1. 假设服务端加密了这么个东西
    file_id = 'secret_file_001'
    # 你想玩的话可以试着吧file ID改一下就行
    encrypt_res = requests.post(
        f'{SERVER_URL}/encrypt',
        json={'file_id': file_id, 'data': '这个File_ID只能被解密一次的文件才对'}
    ).json()
    
    # 2. 假设客户端获取密钥并解密
    key_res = requests.get(
        f'{SERVER_URL}/get_key/{file_id}',
        params={'timestamp': encrypt_res['timestamp']}
    )
    
    if key_res.status_code != 200:
        print("解密失败:", key_res.json())
        return
    
    key = bytes.fromhex(key_res.json()['key'])
    nonce = bytes.fromhex(encrypt_res['nonce'])
    ciphertext = bytes.fromhex(encrypt_res['ciphertext'])
    
    # 解密数据
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    print("解密成功:", plaintext.decode())
    
    # 3. 假设尝试重复解密, 那就失败
    key_res_reuse = requests.get(
        f'{SERVER_URL}/get_key/{file_id}',
        params={'timestamp': encrypt_res['timestamp']}
    )
    print("重复请求结果:", key_res_reuse.json())

if __name__ == '__main__':
    demo_flow()