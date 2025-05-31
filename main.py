from Crypto.Cipher import AES  #pip3 install pycryptodome
import os
import base64

def menu():
    print("\n========= Menu ========")
    print("1. Encriptar")
    print("2. Desencriptar")
    print("3. Ataque de dicionário")
    print("0. Sair")

def encrypt_file(input_file, output_file, password):
    folder = "txt files"
    input_path = os.path.join(folder, input_file)
    output_path = os.path.join(folder, output_file)
    key = password.ljust(16)[:16].encode()

    with open(input_path, 'r', encoding='utf-8') as f:
        text = f.read()

    text_bytes = text.encode('utf-8')
    pad_len = 16 - (len(text_bytes) % 16)
    padded_text_bytes = text_bytes + bytes([pad_len] * pad_len)

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(padded_text_bytes)

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

    print("A desencriptar...")

    decrypted_data = cipher.decrypt(ciphertext)
    pad_len = decrypted_data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding inválido.")
    decrypted_text = decrypted_data[:-pad_len].decode()

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(decrypted_text)

    print(f"\nFicheiro '{input_file}' desencriptado com sucesso para '{output_file}'.")

def dictionary_attack(encrypted_file, wordlist_file, output_file):
    folder = "txt files"
    encrypted_path = os.path.join(folder, encrypted_file)
    wordlist_path = os.path.join(folder, wordlist_file)
    output_path = os.path.join(folder, output_file)

    with open(encrypted_path, 'r', encoding='utf-8') as f:
        encrypted_b64 = f.read()

    encrypted_data = base64.b64decode(encrypted_b64)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    with open(wordlist_path, 'r', encoding='utf-8') as f:
        passwords = [line.strip() for line in f]

    print("A iniciar o ataque...")

    for attempt, password in enumerate(passwords, 1):
        try:
            key = password.ljust(16)[:16].encode()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(ciphertext)

            pad_len = decrypted_data[-1]
            if pad_len < 1 or pad_len > 16:
                raise ValueError("Padding inválido.")

            decrypted_text = decrypted_data[:-pad_len].decode()

            with open(output_path, 'w', encoding='utf-8') as f_out:
                f_out.write(decrypted_text)

            print(f"\nPalavra-passe encontrada: '{password}'")
            print(f"Conteúdo desencriptado guardado em '{output_file}'.")
            return
        except Exception:
            print(f"\rTentativa {attempt}/{len(passwords)}: '{password}'", end='', flush=True)

    print("\nNenhuma palavra-passe válida encontrada.")

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

        elif opcao == "3":
            print("\n--- Ataque de dicionário ---")
            encrypted_file = input("Nome do ficheiro encriptado: ")
            wordlist_file = input("Nome do ficheiro com a lista de palavras: ")
            while True:
                output_file = input("Nome do ficheiro de saída para o conteúdo desencriptado: ")
                if output_file == wordlist_file:
                    print("O ficheiro de saída não pode ser igual ao ficheiro wordlist. Tente outro nome.")
                else:
                    break
            dictionary_attack(encrypted_file, wordlist_file, output_file)

        elif opcao == "0":
            print("A sair do programa...")
            break

        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
