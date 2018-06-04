from json import loads, dumps
from sys import exit, argv
import base64
import urllib2
import binascii

def target_int2bits(target):
    # comprehensive explanation here: bitcoin.stackexchange.com/a/2926/2116

    # get in base 256 as a hex string
    target_hex = int2hex(target)

    bits = "00" if (hex2int(target_hex[: 2]) > 127) else ""
    bits += target_hex # append
    bits = hex2bin(bits)
    length = int2bin(len(bits), 1)

    # the bits value could be zero (0x00) so make sure it is at least 3 bytes
    bits += hex2bin("0000")

    # the bits value could be bigger than 3 bytes, so cut it down to size
    bits = bits[: 3]

    return length + bits

def bits2target_int(bits_bytes):
    exp = bin2int(bits_bytes[: 1]) # exponent is the first byte
    mult = bin2int(bits_bytes[1:]) # multiplier is all but the first byte
    print locals()
    return mult * (2 ** (8 * (exp - 3)))

def int2hex(intval):
    hex_str = hex(intval)[2:]
    if hex_str[-1] == "L":
        hex_str = hex_str[: -1]
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    return hex_str

def hex2int(hex_str):
    return int(hex_str, 16)

def hex2bin(hex_str):
    return binascii.a2b_hex(hex_str)

def int2bin(val, pad_length = False):
    hexval = int2hex(val)
    if pad_length: # specified in bytes
        hexval = hexval.zfill(2 * pad_length)
    return hex2bin(hexval)


def bin2int(s):
	r = 0
	for i in range(0,len(s)):
		r += ord(s[i])*pow(256,i)
	return r

def bin2hex(binary):
    # convert raw binary data to a hex string. also accepts ascii chars (0 - 255)
    return binascii.b2a_hex(binary)


def rpc(method, params):
    data = {
        "jsonrpc": "1.0",
        "id":"curltest",
        "method": method,
        "params": params
    }

    data_json = dumps(data)
    username = argv[1]
    password = argv[2]
    url = "http://127.0.0.1:22555/"
    req = urllib2.Request(url, data_json, {'content-type': 'application/json'})

    base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
    req.add_header("Authorization", "Basic %s" % base64string)

    response_stream = urllib2.urlopen(req)
    json_response = response_stream.read()

    return loads(json_response)

i = 0
INTERVAL = 2016

print "static const struct { uint32_t height; char *hash; time_t timestamp; uint32_t target; } checkpoint_array[] = {"

while True:
    i += INTERVAL
    h = rpc('getblockhash', [i])['result']
    block = rpc('getblock', [h])['result']

    # print dumps(block, indent=2)

    print '    { %d, "%s", %d, 0x%su },' % (
        i, block['hash'], block['time'], bin2hex(target_int2bits(int(block['difficulty'])))
    )

