import base64
import gzip
from urllib.parse import unquote

import pyshark


def XOR(D, K):
    result = []
    for i in range(len(D)):
        c = K[i + 1 & 15]
        if not isinstance(D[i], int):
            d = ord(D[i])
        else:
            d = D[i]
        result.append(d ^ ord(c))
    return b''.join([i.to_bytes(1, byteorder='big') for i in result])


class PHP_XOR_BASE64:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        payload = payload.decode().split(self.pass_ + '=')[1]
        return XOR(base64.b64decode(unquote(payload)), self.key)

    def decrypt_res_payload(self, payload):
        payload = payload[16:-16]
        return gzip.decompress(XOR(base64.b64decode(payload.decode()), self.key))


caps = pyshark.FileCapture("./1.pcap", display_filter="http.response.code!=404 and data-text-lines")

success = []

for cap in caps:
    for line in cap:
        try:
            if ";" not in line.file_data and "<html>" not in line.file_data:
                success.append(line.file_data.encode())
        except:
            continue

# print(success)
decrypter = PHP_XOR_BASE64(pass_='pass', key='3c6e0b8a9c15224a')
for ddata in success:
    if b'pass' in ddata:
        data = decrypter.decrypt_req_payload(ddata)
        print(data.decode('utf-8', 'ignore'))
    else:
        data = decrypter.decrypt_res_payload((ddata))
        print(data.decode('utf-8', 'ignore'))
