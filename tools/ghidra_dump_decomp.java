import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

// 全函数反编译导出 + 符号清单 (headless postScript, 无 Python 依赖)
// 输出: /tmp/ghidra_out/<程序名>_decomp.c 和 _symbols.tsv
// @category PS5 RE
public class ghidra_dump_decomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outDir = "/tmp/ghidra_out";
        new File(outDir).mkdirs();
        String progName = currentProgram.getName().replaceAll("\\.(elf|bin|o)$", "");

        PrintWriter sym = new PrintWriter(new FileWriter(outDir + "/" + progName + "_symbols.tsv"));
        PrintWriter dec = new PrintWriter(new FileWriter(outDir + "/" + progName + "_decomp.c"));

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0, ok = 0;
        sym.println("entry\tname\tsize\tbody");
        while (it.hasNext()) {
            Function f = it.next();
            sym.println(f.getEntryPoint() + "\t" + f.getName() + "\t"
                    + f.getBody().getNumAddresses() + "\t" + f.getBody());
            count++;
            if (monitor.isCancelled()) break;
            DecompileResults res = di.decompileFunction(f, 120, monitor);
            if (res != null && res.decompileCompleted()) {
                ok++;
                dec.println("/* ==== " + f.getName() + " @ " + f.getEntryPoint()
                        + " (" + f.getBody().getNumAddresses() + " bytes) ==== */");
                dec.println(res.getDecompiledFunction().getC());
                dec.println();
            } else {
                dec.println("/* ==== " + f.getName() + " @ " + f.getEntryPoint()
                        + ": DECOMPILE FAILED ==== */\n");
            }
        }
        sym.close();
        dec.close();
        di.dispose();
        println("DECOMP: " + ok + "/" + count + " -> " + outDir + "/" + progName + "_decomp.c");
        println("SYMBOLS: " + outDir + "/" + progName + "_symbols.tsv");
    }
}
