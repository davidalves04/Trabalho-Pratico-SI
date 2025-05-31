def decrypt_file(input_file, output_file, password):
    input_path = os.path.join(FOLDER, input_file)
    output_path = os.path.join(FOLDER, output_file)

    key = password.ljust(16)[:16].encode()

    with open(input_path, 'r', encoding='utf-8') as f:
        encrypted_b64 = f.read()

    encrypted_data = base64.b64decode(encrypted_b64)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = cipher.decrypt(ciphertext)

    # Validação do padding PKCS7
    pad_len = decrypted_data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding inválido.")

    decrypted_text = decrypted_data[:-pad_len].decode('utf-8', errors='ignore')

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(decrypted_text)

    print(f"\nFicheiro '{input_file}' desencriptado com sucesso para '{output_file}'.")


def bruteforce_decrypt(encrypted_file, wordlist_file, output_file="decrypted_output.txt"):
    encrypted_path = os.path.join(FOLDER, encrypted_file)
    wordlist_path = os.path.join(FOLDER, wordlist_file)
    output_path = os.path.join(FOLDER, output_file)

    with open(encrypted_path, 'r', encoding='utf-8') as f:
        encrypted_b64 = f.read()

    encrypted_data = base64.b64decode(encrypted_b64)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    with open(wordlist_path, 'r', encoding='utf-8') as f:
        passwords = [line.strip() for line in f.readlines()]

    print("Iniciando brute-force...")

    for attempt, password in enumerate(passwords, 1):
        try:
            key = password.ljust(16)[:16].encode()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(ciphertext)

            pad_len = decrypted_data[-1]
            if pad_len < 1 or pad_len > 16:
                raise ValueError("Padding inválido.")

            decrypted_text = decrypted_data[:-pad_len].decode('utf-8')

            # Se decodificar e validar padding, senha está correta
            with open(output_path, 'w', encoding='utf-8') as f_out:
                f_out.write(decrypted_text)

            print(f"\n✅ Palavra-passe encontrada: '{password}'")
            print(f"Conteúdo desencriptado salvo em '{output_file}'.")
            return
        except Exception:
            print(f"\rTentativa {attempt}/{len(passwords)}: '{password}'", end='', flush=True)

    print("\n❌ Nenhuma palavra-passe válida encontrada.")
