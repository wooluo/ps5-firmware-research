import ghidra.app.script.GhidraScript;

// 裸内核 dump 前置脚本: 打开 Aggressive Instruction Finder 并在镜像起点播种反汇编
// @category PS5 RE
public class ghidra_pre_aggressive extends GhidraScript {
    @Override
    public void run() throws Exception {
        setAnalysisOption("Aggressive Instruction Finder");
        println("Aggressive Instruction Finder = ON");
    }
}
