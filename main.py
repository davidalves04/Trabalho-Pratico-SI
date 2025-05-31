from Crypto.Cipher import AES #pip3 install pycryptodome
import os
import base64

def menu():
    print("\n=== Menu Inicial ===")
    print("1. Encriptar")
    print("2. Desencriptar")
    print("0. Sair")

def encrypt_file(input_file, output_file, password):
    folder = "txt files"
    input_path = os.path.join(folder, input_file)
    output_path = os.path.join(folder, output_file)
    key = password.ljust(16)[:16].encode()
    
    with open(input_path, 'r', encoding='utf-8') as f:
        text = f.read()

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    pad_len = 16 - len(text) % 16
    padded_text = text + chr(pad_len) * pad_len

    encrypted_data = cipher.encrypt(padded_text.encode())

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(base64.b64encode(iv + encrypted_data).decode())

    print(f"Ficheiro '{input_file}' encriptado com sucesso para '{output_file}'.")

def decrypt_file(input_file, output_file, password):
    folder = "txt files"
    input_path = os.path.join(folder, input_file)
    output_path = os.path.join(folder, output_file)
    key = password.ljust(16)[:16].encode()

    with open(input_path, 'r', encoding='utf-8') as f:
        encrypted_b64 = f.read()

    encrypted_data = base64.b64decode(encrypted_b64)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = b""
    block_size = 16
    total_blocks = len(ciphertext) // block_size

    print("Desencriptando...")

    for i in range(total_blocks):
        block = ciphertext[i*block_size : (i+1)*block_size]
        decrypted_block = cipher.decrypt(block)
        decrypted_data += decrypted_block

        percent = int(((i + 1) / total_blocks) * 100)
        print(f"\rProgresso: {percent}%", end='', flush=True)

    pad_len = decrypted_data[-1]
    decrypted_text = decrypted_data[:-pad_len].decode()

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(decrypted_text)

    print(f"\nFicheiro '{input_file}' desencriptado com sucesso para '{output_file}'.")

def main():
    while True:
        menu()
        opcao = input("Escolha uma opção: ")
        
        if opcao == "1":
            print("\n--- Encriptação ---")
            input_file = input("Nome do ficheiro de entrada: ")
            output_file = input("Nome do ficheiro de saída: ")
            password = input("Palavra-passe: ")
            encrypt_file(input_file, output_file, password)

        elif opcao == "2":
            print("\n--- Desencriptação ---")
            input_file = input("Nome do ficheiro encriptado: ")
            output_file = input("Nome do ficheiro de saída: ")
            password = input("Palavra-passe: ")
            decrypt_file(input_file, output_file, password)

        elif opcao == "0":
            print("Saindo do programa...")
            break

        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
