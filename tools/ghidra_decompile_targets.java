import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

// 定点反编译: 从 /tmp/ghidra_targets.txt 读 VA 列表(每行一个, #注释),
// 反编译这些地址所在函数到 /tmp/ghidra_out/<prog>_targets.c
// @category PS5 RE
public class ghidra_decompile_targets extends GhidraScript {
    @Override
    public void run() throws Exception {
        List<Long> targets = new ArrayList<>();
        for (String line : java.nio.file.Files.readAllLines(new File("/tmp/ghidra_targets.txt").toPath())) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            targets.add(Long.parseUnsignedLong(line.replace("0x", ""), 16));
        }
        String outDir = "/tmp/ghidra_out";
        new File(outDir).mkdirs();
        String progName = currentProgram.getName().replaceAll("\\.(bin|elf)$", "");
        PrintWriter out = new PrintWriter(new FileWriter(outDir + "/" + progName + "_targets.c"));
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        int ok = 0;
        for (Long va : targets) {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va);
            Function f = getFunctionContaining(a);
            if (f == null) { out.println("/* 0x" + Long.toHexString(va) + ": no function found */\n"); continue; }
            DecompileResults res = di.decompileFunction(f, 120, monitor);
            if (res != null && res.decompileCompleted()) {
                ok++;
                out.println("/* ==== " + f.getName() + " @ " + f.getEntryPoint()
                        + " (target 0x" + Long.toHexString(va) + ", " + f.getBody().getNumAddresses() + "B) ==== */");
                out.println(res.getDecompiledFunction().getC());
                out.println();
            } else {
                out.println("/* 0x" + Long.toHexString(va) + " in " + f.getName() + " @ " + f.getEntryPoint() + ": decompile failed */\n");
            }
        }
        out.close();
        println("TARGETS DECOMP: " + ok + "/" + targets.size());
    }
}
