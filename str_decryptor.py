from qiling import Qiling
from unicorn.unicorn_const import UC_MEM_WRITE
from qiling.const import QL_VERBOSE
from capstone import *

begin_addr = 0x0001d164
end_addr = 0x0001d1a4

ql = Qiling([r'libmahoshojo.so'],r'/home/kali/Documents/qiling_rootfs/arm64_linux', verbose=QL_VERBOSE.OFF)

base_addr = ql.mem.get_lib_base(ql.path)
print(f"Library base addr: {hex(base_addr)}")

def decrypt_function_callback(ql, address, size):
    data = ql.mem.read(address, size)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for i in md.disasm(data, address):
        print("[*] 0x{:08x}:\t{} {}".format(i.address-base_addr, i.mnemonic, i.op_str))

def mem_write(ql: Qiling, access: int, address: int, size: int, value: int) -> None:
    assert access == UC_MEM_WRITE
    try:
        decoded_str = bytes.fromhex(f'{value:x}').decode()
        print(f"Intercepted a memory write to {address:#x} (value = {decoded_str[::-1]})")
    except:
        print("An exception has occured")

ql.hook_mem_write(mem_write)
ql.hook_code(decrypt_function_callback, begin=begin_addr+base_addr, end=end_addr+base_addr)
ql.run(begin = begin_addr+base_addr,end=end_addr+base_addr)
