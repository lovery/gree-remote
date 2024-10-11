import argparse
import base64
import sys
import re
import json
import socket

from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


GENERIC_KEY = "a3K8Bx%2r8Y7#xDh"
ENCRYPTION_TYPE = 'ECB'
GENERIC_GCM_KEY = "{yxAHAY_Lm6pbC/<"
GCM_IV = b'\x54\x40\x78\x44\x49\x67\x5a\x51\x6c\x5e\x63\x13'
GCM_ADD = b'qualcomm-test'


class ScanResult:
    ip = ''
    port = 0
    id = ''
    name = '<unknown>'
    key = ''
    sub_unit_cnt = 0
    sub_units = []
    encryption_type = 'ECB'

    def __init__(self, ip, port, id, name='', encryption_type='ECB', sub_unit_cnt=0, key=''):
        self.ip = ip
        self.port = port
        self.id = id
        self.name = name
        self.encryption_type = encryption_type
        self.sub_unit_cnt = sub_unit_cnt
        self.key = key


def send_data(ip, port, data):
    if args.verbose:
        print(f'send_data: ip={ip}, port={port}, data={data}')

    s = socket.socket(type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    s.settimeout(5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(args, 'socket_interface') and args.socket_interface:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.socket_interface.encode('ascii'))
    s.sendto(data, (ip, port))
    return s.recv(1024)


def create_request(tcid, pack_encrypted, i=0, t="pack"):
    request = '{"cid":"app","i":' + str(i) + ',"t":"' + t + '","uid":0,"tcid":"' + tcid + '",'
    if isinstance(pack_encrypted, dict):
        request += '"tag":"' + pack_encrypted["tag"] + '","pack":"' + pack_encrypted["pack"] + '"}'
    else:
        request += '"pack":"' + pack_encrypted + '"}'

    return request


def create_status_request_pack(tcid):
    return '{"cols":["Pow","Mod","SetTem","WdSpd","Air","Blo","Health","SwhSlp","Lig","SwingLfRig","SwUpDn","Quiet",' \
           '"Tur","StHt","TemUn","HeatCoolType","TemRec","SvSt"],"mac":"' + tcid + '","t":"status"}'


def add_pkcs7_padding(data):
    length = 16 - (len(data) % 16)
    padded = data + chr(length) * length
    return padded


def create_ECB_cipher(key):
    return Cipher(algorithms.AES(key.encode('utf-8')), modes.ECB(), backend=default_backend())


def create_GCM_cipher(key):
    cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_GCM, nonce=GCM_IV)
    cipher.update(GCM_ADD)
    return cipher


def decrypt_ECB(pack_encoded, key):
    decryptor = create_ECB_cipher(key).decryptor()
    pack_decoded = base64.b64decode(pack_encoded)
    pack_decrypted = decryptor.update(pack_decoded) + decryptor.finalize()
    pack_unpadded = pack_decrypted[0:pack_decrypted.rfind(b'}') + 1]
    return pack_unpadded.decode('utf-8')


def encrypt_ECB(pack, key):
    encryptor = create_ECB_cipher(key).encryptor()
    pack_padded = add_pkcs7_padding(pack)
    pack_encrypted = encryptor.update(bytes(pack_padded, encoding='utf-8')) + encryptor.finalize()
    pack_encoded = base64.b64encode(pack_encrypted)
    return pack_encoded.decode('utf-8')


def decrypt_GCM(pack_encoded, tag_encoded, key):
    cipher = create_GCM_cipher(key)
    base64decodedPack = base64.b64decode(pack_encoded)
    base64decodedTag = base64.b64decode(tag_encoded)
    decryptedPack = cipher.decrypt_and_verify(base64decodedPack, base64decodedTag)
    decodedPack = decryptedPack.replace(b'\xff', b'').decode('utf-8')
    return decodedPack


def encrypt_GCM(pack, key):
    encrypted_data, tag = create_GCM_cipher(key).encrypt_and_digest(pack.encode("utf-8"))
    encrypted_pack = base64.b64encode(encrypted_data).decode('utf-8')
    tag = base64.b64encode(tag).decode('utf-8')
    data = {
        "pack": encrypted_pack,
        "tag": tag
    }
    return data


def decrypt(resp, key, enc_type):
    if enc_type == 'GCM':
        return decrypt_GCM(resp['pack'], resp['tag'], key)

    return decrypt_ECB(resp['pack'], key)


def decrypt_generic(resp, enc_type):
    if enc_type == 'GCM':
        return decrypt_GCM(resp['pack'], resp['tag'], GENERIC_GCM_KEY)

    return decrypt_ECB(resp['pack'], GENERIC_KEY)


def encrypt(pack, key, enc_type):
    if enc_type == 'GCM':
        return encrypt_GCM(pack, key)

    return encrypt_ECB(pack, key)


def encrypt_generic(pack, enc_type):
    if enc_type == 'GCM':
        return encrypt_GCM(pack, GENERIC_GCM_KEY)

    return encrypt_ECB(pack, GENERIC_KEY)


def search_devices():
    print(f'Searching for devices using broadcast address: {args.broadcast}')

    s = socket.socket(type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    s.settimeout(5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if hasattr(args, 'socket_interface') and args.socket_interface:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.socket_interface.encode('ascii'))
    s.sendto(b'{"t":"scan"}', (args.broadcast, 7000))

    results = []

    while True:
        try:
            (data, address) = s.recvfrom(1024)

            if len(data) == 0:
                continue

            raw_json = data[0:data.rfind(b"}") + 1]

            if args.verbose:
                print(f'search_devices: data={data}, raw_json={raw_json}')

            resp = json.loads(raw_json)

            encryption_type = 'ECB'
            if 'tag' in resp:
                encryption_type = 'GCM'
                if args.verbose:
                    print('Setting the encryption to GCM because tag property is present in the response')

            decrypted_pack = decrypt_generic(resp, encryption_type)
            pack = json.loads(decrypted_pack)

            cid = pack['cid'] if 'cid' in pack and len(pack['cid']) > 0 else \
                resp['cid'] if 'cid' in resp else '<unknown-cid>'

            if encryption_type != 'GCM' and 'ver' in pack:
                ver = re.search(r'(?<=V)[0-9]+(?<=.)', pack['ver'])
                if int(ver.group(0)) >= 2:
                    print('Set GCM encryption because version in search response is 2 or later')
                    encryption_type = 'GCM'

            results.append(ScanResult(
                address[0],
                address[1],
                cid,
                pack['name'] if 'name' in pack else '<unknown>',
                encryption_type,
                pack['subCnt'] if 'subCnt' in pack else 0
            ))

            if args.verbose:
                print(f'search_devices: pack={pack}')

        except socket.timeout:
            print(f'Search finished, found {len(results)} device(s)')
            break

    if len(results) > 0:
        for r in results:
            bind_device(r)


def bind_device(search_result):
    print(f'Binding device: {search_result.ip} ({search_result.name}, ID: {search_result.id}, '
          'encryption: {search_result.encryption_type})')

    pack = '{"mac":"%s","t":"bind","uid":0}' % search_result.id
    pack_encrypted = encrypt_generic(pack, search_result.encryption_type)
    request = create_request(search_result.id, pack_encrypted, 1)
    try:
        result = send_data(search_result.ip, 7000, bytes(request, encoding='utf-8'))
    except socket.timeout:
        if args.verbose:
            print(f'Device {search_result.ip} is not responding on bind request encryped with '
                  '{search_result.encryption_type}')

        if search_result.encryption_type != 'GCM':
            search_result.encryption_type = 'GCM'
            if args.verbose:
                print(f'Device {search_result.ip} change encryption to "GCM" and try to bind again')
            bind_device(search_result)

        return

    response = json.loads(result)
    if response["t"] == "pack":
        pack_decrypted = decrypt_generic(response, search_result.encryption_type)
        bind_resp = json.loads(pack_decrypted)

        if args.verbose:
            print(f'bind_device: resp={bind_resp}')

        if 't' in bind_resp and bind_resp["t"].lower() == "bindok":
            search_result.key = bind_resp['key']
            print(f'Bind to {search_result.id} succeeded, key = {search_result.key}')

    if search_result.sub_unit_cnt > 0:
        if args.verbose:
            print(f'Device {search_result.id}, has {search_result.sub_unit_cnt} sub units try to retrive their mac '
                  'addressess')
        getSubUnitData(search_result)


def getSubUnitData(device):
    sub_list_pack = '{"mac":"%s"}' % device.id
    sub_list_pack_encrypted = encrypt(sub_list_pack, device.key, device.encryption_type)

    sub_list_request = create_request(device.id, sub_list_pack_encrypted, 1, 'sub_list')
    sub_list_result = send_data(device.ip, 7000, bytes(sub_list_request, encoding='utf-8'))
    sub_list_response = json.loads(sub_list_result)
    if args.verbose:
        print(f'sub_list response is {sub_list_response}')

    sub_list_pack_decrypted = decrypt(sub_list_response, device.key, device.encryption_type)
    sub_list_decrypted_response = json.loads(sub_list_pack_decrypted)

    if args.verbose:
        print(f'sub_list decrypted response is {sub_list_decrypted_response}')

    if 'list' in sub_list_decrypted_response:
        if args.verbose:
            print(f'There is list property in the response of sub_list request: {sub_list_decrypted_response["list"]}')

        for sub_unit in sub_list_decrypted_response['list']:
            if args.verbose:
                print(f'in loop of list with itm {sub_unit}')

            if 'mac' in sub_unit:
                if args.verbose:
                    print(f'mac proprty present {sub_unit["mac"]}')
                device.sub_units.append(sub_unit['mac'])
            else:
                print('missing mac property')
    else:
        if args.verbose:
            print('There isnt a list proprty in the response of sub_list request')


def get_param():
    print(f'Getting parameters: {", ".join(args.params)}')

    cols = ','.join(f'"{i}"' for i in args.params)

    pack = f'{{"cols":[{cols}],"mac":"{args.sub if args.sub else args.id}","t":"status"}}'
    data_encrypted = encrypt(pack, args.key, ENCRYPTION_TYPE)
    request = create_request(args.id, data_encrypted, 0)
    result = send_data(args.client, 7000, bytes(request, encoding='utf-8'))

    response = json.loads(result)

    if args.verbose:
        print(f'get_param: response={response}')

    if response["t"] == "pack":
        pack_decrypted = decrypt(response, args.key, ENCRYPTION_TYPE)
        pack_json = json.loads(pack_decrypted)

        if args.verbose:
            print(f'get_param: pack={response["pack"]}, json={pack_json}')

        for col, dat in zip(pack_json['cols'], pack_json['dat']):
            print(f'{col} = {dat}')


def set_param():
    kv_list = [i.split('=') for i in args.params]
    errors = [i for i in kv_list if len(i) != 2]

    if len(errors) > 0:
        print(f'Invalid parameters detected: {errors}')
        sys.exit(1)

    print(f'Setting parameters: {", ".join("=".join(i) for i in kv_list)}')

    opts = ','.join(f'"{i[0]}"' for i in kv_list)
    ps = ','.join(i[1] for i in kv_list)

    pack = f'{{"opt":[{opts}],"p":[{ps}],"t":"cmd"'

    if args.sub is None:
        pack += '}'
    else:
        pack += f',"sub":"{args.sub}"}}'

    print(pack)

    data_encrypted = encrypt(pack, args.key, ENCRYPTION_TYPE)
    request = create_request(args.id, data_encrypted, 0)
    result = send_data(args.client, 7000, bytes(request, encoding='utf-8'))

    response = json.loads(result)

    if args.verbose:
        print(f'set_param: response={response}')

    if response["t"] == "pack":
        pack = response["pack"]

        pack_decrypted = decrypt(response, args.key, ENCRYPTION_TYPE)
        pack_json = json.loads(pack_decrypted)

        if args.verbose:
            print(f'set_param: pack={pack}')

        if pack_json['r'] != 200:
            print('Failed to set parameter')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_help = True
    parser.add_argument('command', help='You can use the following commands: search, bind, get, set')
    parser.add_argument('-c', '--client', help='IP address of the client device')
    parser.add_argument('-p', '--port', help='Port of the client device, default 7000')
    parser.add_argument('-b', '--broadcast', help='Broadcast IP address of the network the devices connecting to')
    parser.add_argument('-i', '--id', help='Unique ID of the device (mac address)')
    parser.add_argument('-s', '--sub', help='Unique ID of a sub unit device (mac address)')
    parser.add_argument('-k', '--key', help='Unique encryption key of the device')
    parser.add_argument('-e', '--encryption', help='Set the encryption type AES128 used: ECB(default), GCM')
    parser.add_argument('--verbose', help='Enable verbose logging', action='store_true')
    if sys.platform == 'linux':
        parser.add_argument('--socket-interface', help='Bind the socket to a specific network interface')
    parser.add_argument('params', nargs='*', default=None, type=str)

    args = parser.parse_args()

    if args.encryption is None:
        ENCRYPTION_TYPE = 'ECB'
    else:
        ENCRYPTION_TYPE = args.encryption

    command = args.command.lower()
    if command == 'search':
        if args.broadcast is None:
            print('Error: search command requires a broadcast IP address')
            sys.exit(1)
        search_devices()
    elif command == 'bind':
        if args.params is None or args.client is None or args.id is None:
            print('Error: bind command requires a client IP (-c) and a device ID (-i), optional port (-p) '
                  'and encryption type (-e)')
            sys.exit(1)
        d = ScanResult(args.client, (args.port if args.port else "7000"), args.id, '<unknown>',
                            (args.encryption if args.encryption else 'ECB'))
        bind_device(d)
    elif command == 'get':
        if args.params is None or len(args.params) == 0 or args.client is None or args.id is None or args.key is None:
            print('Error: get command requires a parameter name, a client IP (-c), a device ID (-i) and a device key '
                  '(-k)')
            sys.exit(1)
        get_param()
    elif command == 'set':
        if args.params is None or len(args.params) == 0 or args.client is None or args.id is None or args.key is None:
            print('Error: set command requires at least one key=value pair, a client IP (-c), a device ID (-i) and a '
                  'device key (-k)')
            sys.exit(1)
        set_param()
    else:
        print(f'Error: unknown command "{args.command}"')
        sys.exit(1)
