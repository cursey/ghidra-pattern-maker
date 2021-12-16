//Builds a pattern for the current location
//@author cursey
//@category Search->InstructionPattern
//@keybinding Ctrl-Alt-S
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;

public class PatternMaker extends GhidraScript {

    public void run() throws Exception {
        var listing = currentProgram.getListing();
        var ins = listing.getInstructionAt(currentAddress);
        
        if (ins == null) {
            println("Cursor must be on an instruction!");
            return;
        }

        var pat = "";
        var pat0 = "";
        int numIns = 0;
        
        while (numIns < 20 && ins != null) {
            var proto = ins.getPrototype();
            var mask = proto.getInstructionMask().getBytes();
            var bytes = ins.getBytes();
            
            println("Considering " + ins.toString());
            
            for (var i = 0; i < bytes.length; ++i) {
                if (mask[i] == 0) {
                    pat += ".";
                    pat0 += "? ";
                } else {
                    pat += String.format("\\x%02X", bytes[i]);
                    pat0 += String.format("%02X ", bytes[i]);
                }
            }

            var matches = findBytes(null, pat, 2);
            
            if (matches.length == 0) {
                println("No unique pattern could be made!");
                return;
            } else if (matches.length == 1) {
                println("Unique pattern: " + pat);
                println("Better format: " + pat0);
                return;
            }
            
            ++numIns;
            ins = ins.getNext();
        }
        
        println("Pattern grew too long!");
    }

}
