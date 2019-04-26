#!/usr/bin/python3

import netifaces as ni
import random
import json
import sys

privkey = "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tDQpNSUlCRXdJQkFRUWdEWlN3K2pFZ3dSQWs0MWllYjN4ODlLOERWMlBKUmNZVFAwZXFrckt1QnRDZ2dhVXdnYUlDDQpBUUV3TEFZSEtvWkl6ajBCQVFJaEFQLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vNy8vL3d2DQpNQVlFQVFBRUFRY0VRUVI1dm1aKytkeTdyRldnWXBYT2h3c0hBcHY4MnkzT0tObFo4b0ZiRnZnWG1FZzYybmNtDQpvOFJsWGFUNy9BNFJDS2o5RjdSSXBvVlVHWnhIMEkvN0VOUzRBaUVBLy8vLy8vLy8vLy8vLy8vLy8vLy8vcnF1DQozT2F2U0tBN3Y5SmVqTkEyUVVFQ0FRR2hSQU5DQUFSQlhlOTI1b3RtNFFCejZxSGN4cVJCQTh6ekNOY0VuMVNUDQphdWJQT1lTcXNaT0lUQlp5VDQzUm0rNmd3SVR1dVpVYloxVEVCd2J6RytPb1phcTNYOG5SDQotLS0tLUVORCBFQyBQUklWQVRFIEtFWS0tLS0tDQo="
pubkey = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlIMU1JR3VCZ2NxaGtqT1BRSUJNSUdpQWdFQk1Dd0dCeXFHU000OUFRRUNJUUQvLy8vLy8vLy8vLy8vLy8vLwovLy8vLy8vLy8vLy8vLy8vLy8vKy8vLzhMekFHQkFFQUJBRUhCRUVFZWI1bWZ2bmN1NnhWb0dLVnpvY0xCd0tiCi9Oc3R6aWpaV2ZLQld4YjRGNWhJT3RwM0pxUEVaVjJrKy93T0VRaW8vUmUwU0thRlZCbWNSOUNQK3hEVXVBSWgKQVAvLy8vLy8vLy8vLy8vLy8vLy8vLzY2cnR6bXIwaWdPNy9TWG96UU5rRkJBZ0VCQTBJQUJMSkF5YVQvcisvNgpvZWlxYjl6T2tQeFgzOVNpelBlWXJySzRxQ1VKbGxHNFIzWW1PNXljVGdXYnhYSGc3bnl4SUFORlQ3eEIyV0RjClpRcFJiNHRFakRRPQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0K"
port = 1313
max_num = int(sys.argv[1])
radio = int(sys.argv[2])

def getRand():
    if random.randrange(radio) == 0:
        return True
    return False

config = dict()


ni.ifaddresses('eth0')
ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
num = ip.split('.')[-1]

config['privateKey'] = privkey
config['id'] = num
config['port'] = port
config['peers'] = [{'ip': '192.168.0.' + str(idx), 'port': port, 'publicKey': pubkey, 'connectTo': getRand(), 'id': str(idx)} for idx in range(1, max_num+1) if str(idx) != num]
print(json.dumps(config))

