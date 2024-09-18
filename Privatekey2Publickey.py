import ecdsa
import hashlib


# 从私钥生成公钥
def private_key_to_public_key(private_key_hex: str, compressed: bool = True) -> str:
    # 将私钥转换为字节
    private_key_bytes = bytes.fromhex(private_key_hex)

    # 使用 secp256k1 曲线生成公钥
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key

    if compressed:
        # 压缩公钥: 根据 y 坐标的偶奇性选择前缀 02 或 03
        x = vk.pubkey.point.x()
        return ('02' if vk.pubkey.point.y() % 2 == 0 else '03') + format(x, '064x')
    else:
        # 未压缩公钥: 前缀 04 + x 坐标 + y 坐标
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        return '04' + format(x, '064x') + format(y, '064x')


# 计算Hash160（SHA-256 + RIPEMD-160）
def hash160(public_key_hex: str) -> str:
    # 进行SHA-256哈希
    sha256_hash = hashlib.sha256(bytes.fromhex(public_key_hex)).digest()
    # 进行RIPEMD-160哈希
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    # 返回RIPEMD-160的十六进制表示
    return ripemd160_hash.hex()


# 测试私钥转换为压缩公钥并计算Hash160（十六进制格式的私钥）
private_key = "0000000000000000000000000000000000000000000000000000000000000001"

# 生成压缩公钥
public_key_compressed = private_key_to_public_key(private_key, compressed=True)
print(f"压缩公钥: {public_key_compressed}")

# 生成Hash160
public_key_hash160 = hash160(public_key_compressed)
print(f"Hash160: {public_key_hash160}")
