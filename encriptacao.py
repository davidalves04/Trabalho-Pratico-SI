from Crypto.Cipher import AES
import sys
import os
import base64

def encrypt_file(input_file, output_file, password):
    #Garante que a senha tem 16 bytes
    key = password.ljust(16)[:16].encode()

    #Lê o conteúdo do ficheiro
    with open(input_file, 'r', encoding='utf-8') as f:
        text = f.read()

    #Gera um IV (Initialization Vector) aleatório
    iv = os.urandom(16)

    #Cria o cifrador AES no modo CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)

    #Adiciona o padding ao texto (PKCS7)
    pad_len = 16 - len(text) % 16
    padded_text = text + chr(pad_len) * pad_len

    #Encripta o texto
    encrypted_data = cipher.encrypt(padded_text.encode())

    #Escreve o texto encriptado em base64, junto com o IV
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(iv + encrypted_data).decode())

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python main.py <input_file> <output_file> <password>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    password = sys.argv[3]

    encrypt_file(input_file, output_file, password)
    print(f"Ficheiro '{input_file}' encriptado para '{output_file}'.")
