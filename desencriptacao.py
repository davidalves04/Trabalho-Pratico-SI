from Crypto.Cipher import AES
import sys
import base64
import time

def decrypt_file(input_file, output_file, password):
    # Garantir que a senha tem 16 bytes (AES-128)
    key = password.ljust(16)[:16].encode()

    with open(input_file, 'r', encoding='utf-8') as f:
        encrypted_b64 = f.read()

    encrypted_data = base64.b64decode(encrypted_b64)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    block_size = 16
    total_blocks = len(ciphertext) // block_size
    decrypted_data = b""

    print("Desencriptando...")

    for i in range(total_blocks):
        block = ciphertext[i*block_size : (i+1)*block_size]
        decrypted_block = cipher.decrypt(block)
        decrypted_data += decrypted_block

        # Mostrar progresso (simples)
        percent = int(((i + 1) / total_blocks) * 100)
        print(f"\rProgresso: {percent}%", end='', flush=True)
        time.sleep(0.01)  # Só para tornar visível o progresso

    print("\nDesencriptação completa.")

    # Remover o padding PKCS7
    pad_len = decrypted_data[-1]
    decrypted_text = decrypted_data[:-pad_len].decode()

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(decrypted_text)

# Exemplo de uso
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python decrypt.py <input_file> <output_file> <password>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    password = sys.argv[3]

    decrypt_file(input_file, output_file, password)
    print(f"Ficheiro '{input_file}' desencriptado para '{output_file}'.")
