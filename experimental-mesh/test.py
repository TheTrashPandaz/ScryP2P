from urllib.request import urlopen
import re

def getPublicIp():
    data = str(urlopen('http://checkip.dyndns.com/').read())
    print(data)
    return re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(data).group(1)
    
god = (getPublicIp())

print(god)
print("hell yeah")