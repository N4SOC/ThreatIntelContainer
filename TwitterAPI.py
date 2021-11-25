import datetime
import config
import requests

list1 = []
domain = config.domain1
client_id = config.client_id1
secret = config.secret1
authExpiry = datetime.datetime.now()
authToken = ""
subSize = 100
z = open('today.csv', 'r')
g = z.readlines()

def getTwitterData():
  out = []
  for lineD in g :
    line = lineD.split(",")
    d1 = {}
    d1["date"] = line[0]
    d1["user"] = line[1]
    d1["IOC_type"] = line[2]
    d1["IOC"] = line[3]
    d1["threat_type"] = line[4]
    d1["twitter_url"] = line[5]
    out.append(d1)
  return(out)

def getAuth():
  global authExpiry, authToken
  expDelta = authExpiry - datetime.datetime.now()
  if expDelta.total_seconds() <= 0:  # token expired or not yet generated
      url = f"https://login.microsoftonline.com/{domain}/oauth2/v2.0/token"
      payload = f"client_id={client_id}&scope=https%3A//graph.microsoft.com/.default%0A&client_secret={secret}&grant_type=client_credentials"
      response = requests.post(url, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=payload,).json()
      authExpiry = datetime.datetime.now() + datetime.timedelta(seconds=int(response["expires_in"]))
      authToken = response["access_token"]
  return authToken

indicatorObjects=[]

indicators = getTwitterData()

for indicator in indicators:
  if ((indicator["IOC_type"]) == "ip"):
    indicatorObj={
    "action": "alert",
    "activityGroupNames": [""],
    "confidence": 0,
    "description": indicator["threat_type"],
    "expirationDateTime": "2022-02-01T21:43:37.5031462+00:00",
    "externalId": indicator["twitter_url"],
    "networkIPv4": indicator["IOC"],
    "killChain": [],
    "malwareFamilyNames": [],
    "severity": 4,
    "tags": [],
    "targetProduct": "Azure Sentinel",
    "threatType": "WatchList",
    "tlpLevel": "green"
  }
  if ((indicator["IOC_type"]) == "sha256"):
    indicatorObj={
    "action": "alert",
    "activityGroupNames": [""],
    "confidence": 0,
    "description": indicator["threat_type"],
    "expirationDateTime": "2022-02-01T21:43:37.5031462+00:00",
    "externalId": indicator["twitter_url"],
    "fileHashType": "sha256",
    "fileHashValue": indicator["IOC"],
    "killChain": [],
    "malwareFamilyNames": [],
    "severity": 4,
    "tags": [],
    "targetProduct": "Azure Sentinel",
    "threatType": "WatchList",
    "tlpLevel": "green"
    }
  if ((indicator["IOC_type"]) == "md5"):
      indicatorObj={
      "action": "alert",
      "activityGroupNames": [""],
      "confidence": 0,
      "description": indicator["threat_type"],
      "expirationDateTime": "2022-02-01T21:43:37.5031462+00:00",
      "externalId": indicator["twitter_url"],
      "fileHashType": "md5",
      "fileHashValue": indicator["IOC"],
      "killChain": [],
      "malwareFamilyNames": [],
      "severity": 4,
      "tags": [],
      "targetProduct": "Azure Sentinel",
      "threatType": "WatchList",
      "tlpLevel": "green"
    }
  if ((indicator["IOC_type"]) == "domain" ):
    indicatorObj={
    "action": "alert",
    "activityGroupNames": [""],
    "confidence": 0,
    "description": indicator["threat_type"],
    "expirationDateTime": "2022-02-01T21:43:37.5031462+00:00",
    "externalId": indicator["twitter_url"],
    "domainName": indicator["IOC"],
    "killChain": [],
    "malwareFamilyNames": [],
    "severity": 4,
    "tags": [],
    "targetProduct": "Azure Sentinel",
    "threatType": "WatchList",
    "tlpLevel": "green"
    }
  if ((indicator["IOC_type"]) == "url" ):
      indicatorObj={
      "action": "alert",
      "activityGroupNames": [""],
      "confidence": 0,
      "description": indicator["threat_type"],
      "expirationDateTime": "2022-02-01T21:43:37.5031462+00:00",
      "externalId": indicator["twitter_url"],
      "url": indicator["IOC"],
      "killChain": [],
      "malwareFamilyNames": [],
      "severity": 4,
      "tags": [],
      "targetProduct": "Azure Sentinel",
      "threatType": "WatchList",
      "tlpLevel": "green"
    }
    
  indicatorObjects.append(indicatorObj)

print("Script START")
print (len(indicatorObjects))

token = getAuth()
url = f"https://graph.microsoft.com/beta/security/tiIndicators/submitTiIndicators"
for x in range(0, len(indicatorObjects), subSize):
  postD = {"value" : indicatorObjects[x:x+subSize]}
  response=requests.post(url,json=postD,headers={"Authorization": "Bearer " + token})
  print(x)
  print(response.status_code)