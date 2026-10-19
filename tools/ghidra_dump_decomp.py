# Ghidra headless postScript: 全函数反编译导出 + 符号清单
# 用法: analyzeHeadless <projdir> <name> -import <elf> -scriptPath <dir> \
#         -postScript ghidra_dump_decomp.py -deleteProject
# 输出: /tmp/ghidra_out/<程序名>_decomp.c 和 _symbols.tsv
# @category PS5 RE
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = "/tmp/ghidra_out"
os.makedirs(OUT_DIR, exist_ok=True)
prog_name = currentProgram.getName().replace(".elf", "").replace(".bin", "")
monitor = ConsoleTaskMonitor()

# 1. 符号清单
sym_path = os.path.join(OUT_DIR, prog_name + "_symbols.tsv")
with open(sym_path, "w") as f:
    f.write("entry\tname\tsize\tbody\n")
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        f.write("%s\t%s\t%d\t%s\n" % (
            func.getEntryPoint(), func.getName(),
            func.getBody().getNumAddresses(), func.getBody()))

# 2. 全量反编译 (大函数 120s 超时)
dec_path = os.path.join(OUT_DIR, prog_name + "_decomp.c")
di = DecompInterface()
di.openProgram(currentProgram)
count = ok = 0
with open(dec_path, "w") as f:
    for func in fm.getFunctions(True):
        count += 1
        res = di.decompileFunction(func, 120, monitor)
        if res.decompileCompleted():
            ok += 1
            f.write("/* ==== %s @ %s (%d bytes) ==== */\n" % (
                func.getName(), func.getEntryPoint(),
                func.getBody().getNumAddresses()))
            f.write(res.getDecompiledFunction().getC())
            f.write("\n\n")
        else:
            f.write("/* ==== %s @ %s: DECOMPILE FAILED ==== */\n\n" % (
                func.getName(), func.getEntryPoint()))
print("DECOMP: %d/%d functions -> %s" % (ok, count, dec_path))
print("SYMBOLS: %s" % sym_path)
