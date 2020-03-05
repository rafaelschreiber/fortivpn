#!/usr/bin/env python3
import sys
import json
import getpass
import os
import time
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random


CONFIGFILE = os.getenv("HOME") + "/.fortivpn.conf"


class Bookmark:
    def __init__(self, hostname=None, port=None, user=None,
                 password=None, trusted_cert=None):
        self.hostname = hostname
        self.port = port
        self.user = user
        self.password = password
        self.trusted_cert = trusted_cert

    def exportJSON(self):
        return dict(hostname=self.hostname, port=self.port,
                    user=self.user, password=self.password,
                    trusted_cert=self.trusted_cert)

    def importJSON(self, data):
        if "hostname" in data:
            self.hostname = data["hostname"]
        if "port" in data:
            self.port = data["port"]
        if "user" in data:
            self.user = data["user"]
        if "password" in data:
            self.password = data["password"]
        if "trusted_cert" in data:
            self.trusted_cert = data["trusted_cert"]


def encrypt(key, source):
    key = bytes(key, "utf8")
    source = bytes(source, "utf8")
    key = SHA256.new(key).digest()
    IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size
    source += bytes([padding]) * padding
    data = IV + encryptor.encrypt(source)
    return base64.b64encode(data).decode("latin-1")


def decrypt(key, source):
    key = bytes(key, "utf8")
    source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()
    IV = source[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])
    padding = data[-1]
    if data[-padding:] != bytes([padding]) * padding:
        return False
    return data[:-padding]


def readConfigFile(path):
    with open(path, 'r') as configfile:
        configfilecontent = configfile.readlines()
        if configfilecontent[0] == "!CRYPTED\n":
            crypted = True
            configfilecontent = configfilecontent[1:]
        else:
            crypted = False
        filecontent = str()
        for line in configfilecontent:
            filecontent += line
        configfile.close()
    return filecontent, crypted


def firstRun():
    print("Welcome, you are running this program for the first time.")
    print("Do you want to encrypt your bookmark file? (y/n)")
    while True:
        ans = str(input(">>> ")).lower()
        if ans in ('y', 'n'):
            break
        else:
            print("Invalid input!\n")
    print()
    if ans == 'y':
        pwd = promptNewPassword()
        content = encrypt(pwd, "{}")
        writeConfigFile(CONFIGFILE, content, True)
    else:
        writeConfigFile(CONFIGFILE, "{}", False)
    print("Bookmark file created successfully")
    return


def writeConfigFile(path, content, crypted):
    with open(path, 'w+') as configfile:
        if crypted:
            configfile.write("!CRYPTED\n" + content)
        else:
            configfile.write(content)
        configfile.close()
    return True


def printBookmark(bookmark, bookmarkname):
    print(bookmarkname + ":")
    print(f"  Hostname:     {bookmark.hostname}")
    print(f"  Port:         {bookmark.port}")
    print(f"  Username:     {bookmark.user}")
    print(f"  Password:     ", end="")
    for i in range(len(bookmark.password)):
        print("*", end="")
    print()
    if bookmark.trusted_cert is not None:
        print(f"  Trusted-cert: {bookmark.trusted_cert}")


def getBookmarknametoAdd(config):
    print("How do you want to call your Bookmark?")
    while True:
        bookmarkname = str(input(">>> "))
        if bookmarkname.lower() not in config.keys():
            return bookmarkname
        print("Bookmark already exists\n")


def getBookmarkToConnect(config):
    print("To which bookmark do you want to connect?")
    while True:
        bookmarkname = str(input(">>> "))
        if bookmarkname.lower() in config.keys():
            return bookmarkname
        print("Bookmark doesn't exist\n")


def getBookmarknametoDelete(config):
    print("Which bookmark do you want to delete?")
    while True:
        bookmarkname = str(input(">>> "))
        if bookmarkname in config.keys():
            return bookmarkname
        print("Bookmark doesn't exist\n")


def getBookmarknametoEdit(config):
    print("Which bookmark do you want to edit?")
    while True:
        bookmarkname = str(input(">>> "))
        if bookmarkname in config.keys():
            return bookmarkname
        print("Bookmark doesn't exist\n")


def getBookmarknametoList(config):
    print("Which bookmark do you want to list?")
    while True:
        bookmarkname = str(input(">>> "))
        if bookmarkname in config.keys() or bookmarkname in ("all", "*"):
            return bookmarkname
        print("Bookmark doesn't exist\n")


def promptBookmark():
    bookmark = Bookmark()
    print("On which host is your VPN server")
    ans = str(input(">>> "))
    bookmark.hostname = ans
    print("On which port is your VPN server listening (default: 443)")
    ans = str(input(">>> "))
    if len(ans) is 0:
        bookmark.port = 443
    else:
        bookmark.port = int(ans)
    print("VPN account username")
    ans = str(input(">>> "))
    bookmark.user = ans
    print("VPN account password")
    ans = getpass.getpass(">>> ")
    bookmark.password = ans
    print("Trusted certificate hash (default: empty)")
    ans = str(input(">>> "))
    if len(ans) is not 0:
        bookmark.trusted_cert = ans
    return bookmark


def createLockFile(pid):
    os.system(f"sudo bash -c \"echo {pid} > /tmp/fortivpn.lock\"")


def removeLockFile():
    os.system(f"sudo bash -c \"rm /tmp/fortivpn.lock &>/dev/null\"")


def vpnconnect(bookmark, bookmarkname):
    pid = "{}:{}".format(bookmarkname, time.time_ns())
    if bookmark.trusted_cert is None:
        cmd = f"bash -c \"echo \'{bookmark.password}\' | sudo openfortivpn {bookmark.hostname}:{bookmark.port} -u {bookmark.user} &>/tmp/{pid}.txt &\""
    else:
        cmd = f"bash -c \"echo \'{bookmark.password}\' | sudo openfortivpn {bookmark.hostname}:{bookmark.port} --trusted-cert={bookmark.trusted_cert} -u {bookmark.user} &>/tmp/{pid}.txt &\""
    createLockFile(pid)
    os.system(cmd)
    time.sleep(2)
    with open("/tmp/" + pid + ".txt", 'r') as logfile:
        logcontent = logfile.read()
        if "ERROR:" in logcontent:
            print(f"Error occured while connecting to the VPN.\nCheck error log at /tmp/{pid}.txt")
            removeLockFile()
            return 2
        elif "Tunnel is up and running." in logcontent:
            print(f"Tunnel is up and running. Check log with fortivpn log")
            return


def promptNewPassword():
    while True:
        print("Enter the password with which you want to encrypt your bookmark file:")
        pwd1 = getpass.getpass(">>> ")
        print("and again...")
        pwd2 = getpass.getpass(">>> ")
        if pwd1 == pwd2:
            return pwd1
        print("Passwords don't match. Try again\n")


def showHelp():
    helpText = """fortivpn - A simple utility to manage Forti VPN connections
    
fortivpn connect <bookmark>
fortivpn list [bookmark]
fortivpn log
fortivpn disconnect
fortivpn add [bookmark]
fortivpn rm [bookmark]
fortivpn edit [bookmark]
fortivpn encrypt
fortivpn decrypt
fortivpn help 
    """
    print(helpText)


def main():
    if len(sys.argv) <= 1:
        showHelp()
        return 1
    
    if sys.argv[1].lower() in ("help",):
        showHelp()
        return 0

    elif sys.argv[1].lower() in ("disconnect",):
        if not os.path.isfile("/tmp/fortivpn.lock"):
            print("There are no active VPN tunnels")
            return 1
        removeLockFile()
        os.system(f"sudo bash -c \"killall -2 openfortivpn &>/dev/null\"")
        print("Tunnel closed")
        return 0

    elif sys.argv[1].lower() in ("log",):
        if not os.path.isfile("/tmp/fortivpn.lock"):
            print("There are no active VPN tunnels")
            return 1
        with open("/tmp/fortivpn.lock", 'r') as lockfile:
            logfilename = lockfile.readline()[:-1]
            lockfile.close()
        os.system(f"tail -f -n +1 /tmp/{logfilename}.txt")
        return 0

    # check for first run
    if not os.path.exists(CONFIGFILE):
        firstRun()
        return 0

    # read config file and decrypt if needed
    config, crypted = readConfigFile(CONFIGFILE)
    if crypted:
        print("Your bookmark file is enrypted. Enter your passwort to decrypt it")
        pwd = getpass.getpass(">>> ")
        config = decrypt(pwd, config)
        if not config:
            print("Wrong password, cannot decrypt your bookmark file")
            return 1

    try:
        config = json.loads(config)
    except json.decoder.JSONDecodeError:
        print("Invalid bookmark file")
        return 1

    # interpret bookmark file
    for bookmark in config.keys():
        temp = Bookmark()
        temp.importJSON(config[bookmark])
        config[bookmark] = temp

    if sys.argv[1].lower() in ("add",):
        if len(sys.argv) >= 3:
            if sys.argv[2].lower() not in config.keys():
                bookmarkname = sys.argv[2]
            else:
                print("The specified bookmarkname already exists\n")
                bookmarkname = getBookmarknametoAdd(config)
        else:
            bookmarkname = getBookmarknametoAdd(config)
        config[bookmarkname.lower()] = promptBookmark()
        print(f"Successfully added bookmark: {bookmarkname}")

    elif sys.argv[1].lower() in ("list", "ls"):
        if len(sys.argv) > 2:
            if sys.argv[2].lower() in config.keys():
                bookmarkname = sys.argv[2].lower()
                printBookmark(config[bookmarkname], bookmarkname)
            elif sys.argv[2].lower() in ('all', '*'):
                for bookmark in config.keys():
                    printBookmark(config[bookmark], bookmark)
            else:
                print("The specified bookmark doesn't exist\n")
                bookmarkname = getBookmarknametoList(config)
                if bookmarkname.lower() in ('all', '*'):
                    for bookmark in config.keys():
                        printBookmark(config[bookmark], bookmark)
                else:
                    printBookmark(config[bookmarkname], bookmarkname)
        else:
            for bookmark in config.keys():
                print(bookmark)
        return 0

    elif sys.argv[1].lower() in ("rm",):
        if len(sys.argv) > 2:
            if sys.argv[2] in config.keys():
                bookmarkname = sys.argv[2]
            else:
                print("The specified bookmark doesn't exist\n")
                bookmarkname = getBookmarknametoDelete(config)
        else:
            bookmarkname = getBookmarknametoDelete(config)
        config.pop(bookmarkname, None)
        print(f"Successfully removed bookmark: {bookmarkname}")

    elif sys.argv[1].lower() in ("connect", "conn"):
        if os.path.isfile("/tmp/fortivpn.lock"):
            print("A tunnel is already running.\nPlease stop the current connection with fortivpn disconnect")
            return 1
        if len(sys.argv) >= 3:
            if sys.argv[2].lower() in config.keys():
                return vpnconnect(config[sys.argv[2].lower()],
                                  sys.argv[2].lower())
            else:
                print("The specified bookmarkname doesn't exist\n")
                bookmarkname = getBookmarkToConnect(config)
        else:
            bookmarkname = getBookmarkToConnect(config)
        return vpnconnect(config[bookmarkname.lower()],
                          bookmarkname.lower())

    # encrypt bookmarkfile
    elif sys.argv[1] in ("encrypt",):
        if crypted:
            print("Bookmark file is already encrypted. Nothing todo")
            return 0
        pwd = promptNewPassword()
        crypted = True

    # decrypt bookmarkfile
    elif sys.argv[1] in ("decrypt",):
        if not crypted:
            print("Bookmark file is already decrypted. Nothing todo")
            return 0
        crypted = False

    else:
        showHelp()
        return 1

    for bookmark in config.keys():
        config[bookmark] = config[bookmark].exportJSON()

    config = json.dumps(config, indent=4)
    if crypted:
        content = encrypt(pwd, config)
    else:
        content = config
    writeConfigFile(CONFIGFILE, content, crypted)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(3)
