from pwn import * # pip install pwntools
import json

HOST = "socket.cryptohack.org"
PORT = 13371

r = remote(HOST, PORT)
l = listen(PORT)

def json_recv():
    line = r.readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)


print(r.readline())
print(r.readline())
print(r.readline())
print(r.readline())

# request = {
#     "buy": "flag",
#     "p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff",
#     "g": "0x02",
#     "B": "0xb32b46088b35def0fb48970dbdbfc0eaaf02c2b67e175c9bc465ca88240f17dca43396756089062f788db0a15cd3a91c767a6ad967f7d5c460a3ddd09af84d0299a8518a2ef173836ddd033f5849bab0811ee2baa3963483fd1beca979c03d27b9a1bb3acaef12f15ae05c738dfe77447c50abd985e287fe004351238a0a13e6cc924d64331590970384eab88593de08da25051211feec677af70c8459b490824c78b8886bc39875741fe03d7465e012701fdff3a5c4f3625a45555172aa100a"
    
# }
# json_send(request)

# response = json_recv()

# print(response)

svr = l.wait_for_connection()
r.send('hello')
print(svr.recv())