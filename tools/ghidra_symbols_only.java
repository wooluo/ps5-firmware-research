import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

// 内核 raw dump 专用: 仅导出函数清单(不做全量反编译, 内核函数太多)
// 输出: /tmp/ghidra_out/<程序名>_symbols.tsv + 函数计数
// @category PS5 RE
public class ghidra_symbols_only extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outDir = "/tmp/ghidra_out";
        new File(outDir).mkdirs();
        String progName = currentProgram.getName().replaceAll("\\.(bin|elf)$", "");

        PrintWriter sym = new PrintWriter(new FileWriter(outDir + "/" + progName + "_symbols.tsv"));
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        sym.println("entry\tname\tsize\tbody");
        while (it.hasNext()) {
            Function f = it.next();
            sym.println(f.getEntryPoint() + "\t" + f.getName() + "\t"
                    + f.getBody().getNumAddresses() + "\t" + f.getBody());
            count++;
        }
        sym.close();
        println("FUNCS: " + count + " -> " + outDir + "/" + progName + "_symbols.tsv");
    }
}
