
import struct, hashlib
path = r"D:\新建文件夹\刷机\root\SukiSU_Nova_v3.0.0-arm64.apk"
data = open(path,'rb').read()
i = data.rfind(b'PK\x05\x06')
cd_off = struct.unpack_from('<I', data, i+16)[0]
magic_off = data.rfind(b'APK Sig Block 42', 0, cd_off)
size_of_block = struct.unpack_from('<Q', data, magic_off-8)[0]
block_start = magic_off + 8 - size_of_block
size1 = struct.unpack_from('<Q', data, block_start)[0]
print("magic_off",magic_off,"cd_off",cd_off,"size_of_block",size_of_block,"size1",size1)
p = block_start+8
pairs_end = magic_off-8
found={}
while p < pairs_end:
    ln = struct.unpack_from('<Q', data, p)[0]
    idv = struct.unpack_from('<I', data, p+8)[0]
    found[idv]=data[p+12:p+8+ln]
    p += 8+ln
print("ids:",{hex(k):len(v) for k,v in found.items()})
v2 = found[0x7109871a]
def lp(buf, off):
    n = struct.unpack_from('<I', buf, off)[0]
    return buf[off+4:off+4+n], off+4+n
signers,_ = lp(v2,0)
signer,_ = lp(signers,0)
signed_data,_ = lp(signer,0)
digests,o2 = lp(signed_data,0)
certs,o3 = lp(signed_data,o2)
cert,o4 = lp(certs,0)
h = hashlib.sha256(cert).hexdigest()
print("cert len",len(cert),hex(len(cert)))
print("cert sha256",h)
print("der head", cert[:20].hex())
want={"947ae944f3de4ed4c21a7e4f7953ecf351bfa2b36239da37a34111ad29993eef":"SukiSU 0x35c",
"f415f4ed9435427e1fdf7f1fccd4dbc07b3d6b8751e4dbcec6f19671f427870b":"RKSU 0x396",
"c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6":"KSU 0x33b",
"52d52d8c8bfbe53dc2b6ff1c613184e2c03013e090fe8905d8e3d5dc2658c2e4":"WKSU 0x381",
"484fcba6e6c43b1fb09700633bf2fb4758f13cb0b2f4457b80d075084b26c588":"KowSU 0x375",
"79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7":"KSUN 0x3e6",
"7e0c6d7278a3bb8e364e0fcba95afaf3666cf5ff3c245a3b63c8833bd0445cc4":"MKSU 384"}
print("MATCH:", want.get(h,"NONE"))
