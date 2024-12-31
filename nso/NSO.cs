using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using K4os.Compression.LZ4;
using System.Security.Cryptography;
using System.Diagnostics.SymbolStore;
using System.Diagnostics.CodeAnalysis;
using System.Resources;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm64;
using Microsoft.VisualBasic.FileIO;
using System.ComponentModel;

namespace swspl.nso
{
    public class NSO
    {
        public NSO(string filepath)
        {
            if (File.Exists(filepath))
            {
                using (BinaryReader reader = new BinaryReader(File.Open(filepath, FileMode.Open), Encoding.UTF8))
                {
                    if (Util.ReadString(reader, 4) != "NSO0")
                    {
                        throw new Exception("NSO::NSO(string) -- Invalid NSO signature.");
                    }

                    string filename = Path.GetFileNameWithoutExtension(filepath);

                    // skip the version and reversed sections
                    reader.ReadBytes(8);

                    uint flags = reader.ReadUInt32();
                    NSOSegment textSeg = new NSOSegment(reader);
                    uint moduleNameOffs = reader.ReadUInt32();
                    NSOSegment rodataSeg = new NSOSegment(reader);
                    uint moduleNameSize = reader.ReadUInt32();
                    NSOSegment dataSeg = new NSOSegment(reader);
                    uint bssSize = reader.ReadUInt32();
                    byte[] moduleID = reader.ReadBytes(0x20);

                    // compressed sizes
                    int textCmprSize = reader.ReadInt32();
                    int roDataCmprSize = reader.ReadInt32();
                    int dataCmprSize = reader.ReadInt32();

                    reader.ReadBytes(0x1C);
                    uint embedOffs = reader.ReadUInt32();
                    uint embedSize = reader.ReadUInt32();
                    uint dynStrOffs = reader.ReadUInt32();
                    uint dynStrSize = reader.ReadUInt32();
                    uint dynSymOffs = reader.ReadUInt32();
                    uint dynSymSize = reader.ReadUInt32();

                    byte[] textHash = reader.ReadBytes(0x20);
                    byte[] roDataHash = reader.ReadBytes(0x20);
                    byte[] dataHash = reader.ReadBytes(0x20);

                    // now we get the final data for each section
                    // .text
                    byte[] text;
                    reader.BaseStream.Seek(textSeg.GetOffset(), SeekOrigin.Begin);
                    // are we compressed?
                    if ((flags & 0x1) != 0)
                    {
                        byte[] bytes = reader.ReadBytes(textCmprSize);
                        text = new byte[textSeg.GetSize()];
                        LZ4Codec.Decode(bytes, text);

                    }
                    else
                    {
                        text = reader.ReadBytes(textSeg.GetSize());
                    }

                    // .rodata
                    byte[] rodata;
                    reader.BaseStream.Seek(rodataSeg.GetOffset(), SeekOrigin.Begin);
                    // are we compressed?
                    if (((flags >> 1) & 0x1) != 0)
                    {
                        byte[] bytes = reader.ReadBytes(roDataCmprSize);
                        rodata = new byte[rodataSeg.GetSize()];
                        LZ4Codec.Decode(bytes, rodata);
                    }
                    else
                    {
                        rodata = reader.ReadBytes(rodataSeg.GetSize());
                    }

                    // .data
                    byte[] data;
                    reader.BaseStream.Seek(dataSeg.GetOffset(), SeekOrigin.Begin);
                    // are we compressed?
                    if (((flags >> 2) & 0x1) != 0)
                    {
                        byte[] bytes = reader.ReadBytes(dataCmprSize);
                        data = new byte[dataSeg.GetSize()];
                        LZ4Codec.Decode(bytes, data);
                    }
                    else
                    {
                        data = reader.ReadBytes(dataSeg.GetSize());
                    }

                    File.WriteAllBytes($"{filename}_text.bin", text);
                    File.WriteAllBytes($"{filename}_data.bin", data);
                    File.WriteAllBytes($"{filename}_rodata.bin", rodata);

                    // now let's check our hashes to ensure we have the right data
                    byte[] textCmprHash = Util.GetSHA(text);
                    byte[] roDataCmprHash = Util.GetSHA(rodata);
                    byte[] dataCmprHash = Util.GetSHA(data);

                    if (Util.ArrayEqual(textCmprHash, textHash))
                    {
                        Console.WriteLine(".text segment hash matches");
                    }
                    else
                    {
                        throw new Exception("NSO::NSO(string) -- .text segment hash mismatch");
                    }

                    if (Util.ArrayEqual(roDataCmprHash, roDataHash))
                    {
                        Console.WriteLine(".rodata segment hash matches");
                    }
                    else
                    {
                        throw new Exception("NSO::NSO(string) -- .rodata segment hash mismatch");
                    }

                    if (Util.ArrayEqual(dataCmprHash, dataHash))
                    {
                        Console.WriteLine(".data segment hash matches");
                    }
                    else
                    {
                        throw new Exception("NSO::NSO(string) -- .data segment hash mismatch");
                    }

                    // our data is valid. we can move on to our dynamic stuff
                    BinaryReader dynReader = new(new MemoryStream(rodata), Encoding.UTF8);
                    
                    /* .buildstr */
                    BuildStr buildStr = new(dynReader);

                    /* .dynstr */
                    dynReader.BaseStream.Seek(dynStrOffs, SeekOrigin.Begin);
                    DynamicStringTable strTbl = new(dynReader, dynStrSize);

                    /* .dynsym */
                    uint numSyms = dynSymSize / 24;
                    dynReader.BaseStream.Seek(dynSymOffs, SeekOrigin.Begin);
                    DynamicSymbolTable dynTbl = new(dynReader, numSyms);

                    // MOD0
                    BinaryReader textReader = new(new MemoryStream(text), Encoding.UTF8);
                    Module module = new(textReader);

                    /* .dynamic */
                    uint dynOffs = module.mDynOffset - dataSeg.GetMemoryOffset();
                    BinaryReader dataReader = new(new MemoryStream(data), Encoding.UTF8);
                    dataReader.BaseStream.Position = dynOffs;
                    DynamicSegment seg = new(dataReader);

                    /* .hash */
                    long hashOffs = seg.GetTagValue<long>(DynamicSegment.TagType.DT_HASH) - rodataSeg.GetMemoryOffset();
                    dynReader.BaseStream.Seek(hashOffs, SeekOrigin.Begin);
                    HashTable hashTbl = new(dynReader);
                    /* .gnu_hash */
                    GNUHashTable gnuHashTbl = new(dynReader);

                    /* .rela.dyn */
                    long relocCount = seg.GetRelocationCount();
                    long relocOffs = seg.GetTagValue<long>(DynamicSegment.TagType.DT_RELA) - rodataSeg.GetMemoryOffset();
                    dynReader.BaseStream.Seek(relocOffs, SeekOrigin.Begin);
                    RelocationTable relocTbl = new(dynReader, relocCount);

                    /* .rela.plt */
                    long pltOffs = seg.GetTagValue<long>(DynamicSegment.TagType.DT_JMPREL) - rodataSeg.GetMemoryOffset();
                    dynReader.BaseStream.Seek(pltOffs, SeekOrigin.Begin);
                    long pltCount = seg.GetTagValue<long>(DynamicSegment.TagType.DT_PLTRELSZ) / 0x14;
                    RelocationPLT plt = new(dynReader, pltCount);

                    /* .got.plt */
                    long gotPltOffs = seg.GetTagValue<long>(DynamicSegment.TagType.DT_PLTGOT) - dataSeg.GetMemoryOffset();
                    GlobalPLT globalPLT = new(dataReader, plt.GetNumJumps());

                    /* .got */
                    long gotStart = dataReader.BaseStream.Position;
                    // getting our .got is a bit more difficult
                    // we do not know where it ends, but we do know it is right after .got.plt ends
                    long gotEnd = seg.GetTagValue<long>(DynamicSegment.TagType.DT_INIT_ARRAY) - dataSeg.GetMemoryOffset();
                    // now let's figure out how many entries we have
                    long gotCount = (gotEnd - gotStart) / 8;

                    List<long> got = new();

                    for (int i = 0; i < gotCount; i++)
                    {
                        got.Add(dataReader.ReadInt64());
                    }

                    /* read the rest of our .text */
                    /* some MOD0s end with padding, some don't. there really isn't a way to tell. */
                    while (true)
                    {
                        // ...so let's read until we hit nonzero
                        if (textReader.ReadUInt32() != 0)
                        {
                            textReader.BaseStream.Position -= 4;
                            break;
                        }
                    }

                    // our functions are relative to the end of MOD0
                    long startPos = textReader.BaseStream.Position;

                    // now we read the remaining portion of .text and map those instructions to symbols
                    Dictionary<string, Arm64Instruction[]> funcs = new();
                    int remainingText = textSeg.GetSize() - (int)textReader.BaseStream.Position;
                    byte[] textBytes = textReader.ReadBytes(remainingText);
                    const Arm64DisassembleMode mode = Arm64DisassembleMode.LittleEndian | Arm64DisassembleMode.Arm;

                    Dictionary<string, List<string>> textfile = new();
                    ulong baseAddr = 0x7100000000;
                    //textfile.Add(".section \".text\", \"ax\"");

                    foreach (DynamicSymbol sym in dynTbl.mSymbols)
                    {
                        List<string> funcStr = new();
                        // symbols tied to a size of 0 are not .text
                        if (sym.mSize == 0)
                        {
                            continue;
                        }

                        string symbolName = strTbl.GetSymbolAtOffs(sym.mStrTableOffs);
                        long pos = (long)sym.mValue - startPos;
                        byte[] funcBytes = textBytes.Skip((int)pos).Take((int)sym.mSize).ToArray();

                        List<ulong> jumps = new();

                        using (CapstoneArm64Disassembler dis = CapstoneDisassembler.CreateArm64Disassembler(mode))
                        {
                            dis.EnableInstructionDetails = true;
                            // we have to enable this due to the fact that TRAP is invalid with capstone
                            dis.EnableSkipDataMode = true;
                            dis.DisassembleSyntax = DisassembleSyntax.Intel;

                            Arm64Instruction[] instrs = dis.Disassemble(funcBytes, pos + startPos);
                            funcs.Add(symbolName, instrs);

                            for (int i = 0; i < instrs.Length; i++)
                            {
                                Arm64Instruction instr = instrs[i];

                                if (instr.Mnemonic == ".byte")
                                {
                                    // TRAP instruction
                                    if (instr.Operand == "0xfe, 0xde, 0xff, 0xe7")
                                    {
                                        funcStr.Add($"\ttrap");
                                    }
                                }
                                // bl need to be defined differently
                                else  if (instr.Mnemonic == "bl")
                                {
                                    ulong oper = Convert.ToUInt64(instr.Operand.Replace("#", ""), 16);

                                    DynamicSymbol? jumpSym = dynTbl.GetSymbolAtAddr(oper);

                                    string jumpSymName = "";

                                    if (jumpSym != null)
                                    {
                                        jumpSymName = $"bl {strTbl.GetSymbolAtOffs(jumpSym.mStrTableOffs)}";
                                    }
                                    else
                                    {
                                        jumpSymName = $"bl fn_{(baseAddr + oper).ToString("X")}";
                                    }

                                    funcStr.Add($"\t{jumpSymName}");
                                }
                                else if (Util.IsBranchInstr(instr.Mnemonic))
                                {
                                    if (instr.Mnemonic == "tbz" || instr.Mnemonic == "tbnz")
                                    {
                                        // second part of the instruction is the addr itself
                                        ulong addr = (ulong)instr.Details.Operands[2].Immediate;

                                        if (!jumps.Contains(addr))
                                        {
                                            jumps.Add(addr);
                                        }

                                        funcStr.Add($"\t{instr.Mnemonic} #{instr.Details.Operands[1].Immediate} loc_{(baseAddr + addr).ToString("X")}");
                                    }
                                    else if (instr.Mnemonic == "cbz")
                                    {
                                        ulong addr = (ulong)instr.Details.Operands[1].Immediate;

                                        if (!jumps.Contains(addr))
                                        {
                                            jumps.Add(addr);
                                        }

                                        funcStr.Add($"\t{instr.Mnemonic} loc_{(baseAddr + addr).ToString("X")}");
                                    }
                                    else
                                    {
                                        // sometimes the compiler can branch to another function without using BL
                                        // make sure we account for it
                                        ulong jmp = Convert.ToUInt64(instr.Operand.Replace("#", ""), 16);
                                        ulong range = (ulong)pos + sym.mSize;
                                        // is our jump in range of our current function?
                                        // if it is, it is a local branch
                                        // if not, it is a function call
                                        if (jmp >= (ulong)pos && jmp <= range)
                                        {
                                            // avoid duplicating jumps
                                            if (!jumps.Contains(jmp))
                                            {
                                                jumps.Add(jmp);
                                            }

                                            funcStr.Add($"\t{instr.Mnemonic} loc_{(baseAddr + jmp).ToString("X")}");
                                        }
                                        else
                                        {
                                            funcStr.Add($"\t{instr.Mnemonic} fn_{(baseAddr + jmp).ToString("X")}");
                                        }
                                    }

                                }
                                else
                                {
                                    funcStr.Add($"\t{instr}");
                                }
                            }

                            // sort our offsets so we can properly insert them without screwing up other indicies
                            jumps.Sort();

                            // now let's resolve our jumps
                            foreach(ulong jmp in jumps)
                            {
                                // figure out the offset within the function to insert our instruction at
                                ulong offs = jmp - sym.mValue;
                                // now we get the index into our already obtained list of strings
                                int funcIdx = (int)offs / 4;
                                // insert our local string into the function strings...we use the index + indexof to properly account for other jumps already inserted
                                funcStr.Insert(funcIdx + jumps.IndexOf(jmp), $"loc_{(baseAddr + jmp).ToString("X")}:");
                            }
                        }

                        textfile.Add(symbolName, funcStr);
                    }

                    List<string> file = new();

                    foreach(KeyValuePair<string, List<string>> e in textfile) {
                        file.Add($".global {e.Key}");
                        file.Add($"{e.Key}:");
                        foreach(string str in e.Value)
                        {
                            file.Add(str);
                        }
                        file.Add("\n");
                    }

                    File.WriteAllLines("text.s", file.ToArray());
                }
            }
            else
            {
                throw new Exception("NSO::NSO(string) -- File does not exist.");
            }
        }
    }
}
