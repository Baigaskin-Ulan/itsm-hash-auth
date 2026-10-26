import urllib.request

URL = ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
       "Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt")
text = urllib.request.urlopen(URL).read().decode("utf-8", "ignore")
long_ones = [p for p in text.splitlines() if len(p) >= 15]
with open("blocklist.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(long_ones))
print(len(long_ones), "passwords saved to blocklist.txt")