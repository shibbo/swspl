using System.Text;
using K4os.Compression.LZ4;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm64;

namespace swspl.nso
{
    public class NSO
    {
        string mFileName;
        public Dictionary<ulong, List<string>> mTextFile = new();
        public Dictionary<ulong, string> mAddrToSym = new();
        private List<ulong> mUnknownFuncs = new();
        private static readonly ulong BaseAdress = 0x7100000000;
        private DynamicSymbolTable mSymbolTable;
        private DynamicStringTable mStringTable;
        private Dictionary<string, Arm64Instruction[]> mFuncInstructions = new();

        byte[] mTextHash;
        byte[] mDataHash;
        byte[] mRoDataHash;
        byte[] mModuleID;
        NSOSegment mTextSegement;
        NSOSegment mRodataSegment;
        NSOSegment mDataSegment;
        byte[] mText;
        byte[] mData;
        byte[] mRodata;
        Module mModule;
        DynamicSegment mDynamicSegment;
        HashTable mHashTable;
        GNUHashTable mGNUHashTable;
        BuildStr mBuildStr;

        public NSO(string filepath, bool infoOnly)
        {
            mFileName = Path.GetFileName(filepath);
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
                    mTextSegement = new NSOSegment(reader);
                    uint moduleNameOffs = reader.ReadUInt32();
                    mRodataSegment = new NSOSegment(reader);
                    uint moduleNameSize = reader.ReadUInt32();
                    mDataSegment = new NSOSegment(reader);
                    uint bssSize = reader.ReadUInt32();
                    mModuleID = reader.ReadBytes(0x20);

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

                    mTextHash = reader.ReadBytes(0x20);
                    mRoDataHash = reader.ReadBytes(0x20);
                    mDataHash = reader.ReadBytes(0x20);

                    // now we get the final data for each section
                    // .text
                    reader.BaseStream.Seek(mTextSegement.GetOffset(), SeekOrigin.Begin);
                    // are we compressed?
                    if ((flags & 0x1) != 0)
                    {
                        byte[] bytes = reader.ReadBytes(textCmprSize);
                        mText = new byte[mTextSegement.GetSize()];
                        LZ4Codec.Decode(bytes, mText);

                    }
                    else
                    {
                        mText = reader.ReadBytes(mTextSegement.GetSize());
                    }

                    // .rodata
                    reader.BaseStream.Seek(mRodataSegment.GetOffset(), SeekOrigin.Begin);
                    // are we compressed?
                    if (((flags >> 1) & 0x1) != 0)
                    {
                        byte[] bytes = reader.ReadBytes(roDataCmprSize);
                        mRodata = new byte[mRodataSegment.GetSize()];
                        LZ4Codec.Decode(bytes, mRodata);
                    }
                    else
                    {
                        mRodata = reader.ReadBytes(mRodataSegment.GetSize());
                    }

                    // .data=
                    reader.BaseStream.Seek(mDataSegment.GetOffset(), SeekOrigin.Begin);
                    // are we compressed?
                    if (((flags >> 2) & 0x1) != 0)
                    {
                        byte[] bytes = reader.ReadBytes(dataCmprSize);
                        mData = new byte[mDataSegment.GetSize()];
                        LZ4Codec.Decode(bytes, mData);
                    }
                    else
                    {
                        mData = reader.ReadBytes(mDataSegment.GetSize());
                    }

                    // now let's check our hashes to ensure we have the right data
                    byte[] textCmprHash = Util.GetSHA(mText);
                    byte[] roDataCmprHash = Util.GetSHA(mRodata);
                    byte[] dataCmprHash = Util.GetSHA(mData);

                    if (!Util.ArrayEqual(textCmprHash, mTextHash))
                    {
                        throw new Exception("NSO::NSO(string) -- .text segment hash mismatch");
                    }

                    if (!Util.ArrayEqual(roDataCmprHash, mRoDataHash))
                    {
                        throw new Exception("NSO::NSO(string) -- .rodata segment hash mismatch");
                    }

                    if (!Util.ArrayEqual(dataCmprHash, mDataHash))
                    {
                        throw new Exception("NSO::NSO(string) -- .data segment hash mismatch");
                    }

                    // our data is valid. we can move on to our dynamic stuff
                    BinaryReader dynReader = new(new MemoryStream(mRodata), Encoding.UTF8);

                    /* .buildstr */
                    mBuildStr = new(dynReader);

                    /* .dynstr */
                    dynReader.BaseStream.Seek(dynStrOffs, SeekOrigin.Begin);
                    mStringTable = new(dynReader, dynStrSize);

                    /* .dynsym */
                    uint numSyms = dynSymSize / 24;
                    dynReader.BaseStream.Seek(dynSymOffs, SeekOrigin.Begin);
                    mSymbolTable = new(dynReader, numSyms);

                    // MOD0
                    BinaryReader textReader = new(new MemoryStream(mText), Encoding.UTF8);
                    mModule = new(textReader);

                    /* .dynamic */
                    uint dynOffs = mModule.mDynOffset - mDataSegment.GetMemoryOffset();
                    BinaryReader dataReader = new(new MemoryStream(mData), Encoding.UTF8);
                    dataReader.BaseStream.Position = dynOffs;
                    mDynamicSegment = new(dataReader);

                    /* .hash */
                    long hashOffs = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_HASH) - mRodataSegment.GetMemoryOffset();
                    dynReader.BaseStream.Seek(hashOffs, SeekOrigin.Begin);
                    mHashTable = new(dynReader);
                    /* .gnu_hash */
                    mGNUHashTable = new(dynReader);

                    /* .rela.dyn */
                    long relocCount = mDynamicSegment.GetRelocationCount();
                    long relocOffs = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_RELA) - mRodataSegment.GetMemoryOffset();
                    dynReader.BaseStream.Seek(relocOffs, SeekOrigin.Begin);
                    RelocationTable relocTbl = new(dynReader, relocCount);

                    /* .rela.plt */
                    long pltOffs = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_JMPREL) - mRodataSegment.GetMemoryOffset();
                    dynReader.BaseStream.Seek(pltOffs, SeekOrigin.Begin);
                    long pltCount = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_PLTRELSZ) / 0x14;
                    RelocationPLT plt = new(dynReader, pltCount);

                    /* .got.plt */
                    long gotPltOffs = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_PLTGOT) - mDataSegment.GetMemoryOffset();
                    GlobalPLT globalPLT = new(dataReader, plt.GetNumJumps());

                    /* .got */
                    long gotStart = dataReader.BaseStream.Position;
                    // getting our .got is a bit more difficult
                    // we do not know where it ends, but we do know it is right after .got.plt ends
                    long gotEnd = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_INIT_ARRAY) - mDataSegment.GetMemoryOffset();
                    // now let's figure out how many entries we have
                    long gotCount = (gotEnd - gotStart) / 8;

                    List<long> got = new();

                    for (int i = 0; i < gotCount; i++)
                    {
                        got.Add(dataReader.ReadInt64());
                    }

                    /* if we are only dumping info, we can stop here. */
                    if (infoOnly)
                    {
                        return;
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
                    int remainingText = mTextSegement.GetSize() - (int)textReader.BaseStream.Position;
                    byte[] textBytes = textReader.ReadBytes(remainingText);
                    ParseTextSegment(textBytes, startPos);
                }
            }
            else
            {
                throw new Exception("NSO::NSO(string) -- File does not exist.");
            }
        }

        public void ParseTextSegment(byte[] textBytes, long startPos)
        {
            foreach (DynamicSymbol sym in mSymbolTable.mSymbols)
            {
                string symbolName = mStringTable.GetSymbolAtOffs(sym.mStrTableOffs);
                // symbols tied to a size of 0 are not .text
                if (sym.mSize == 0)
                {
                    continue;
                }

                /* check to see if our symbol is even in the .text section */
                if (!mTextSegement.IsInRange((uint)sym.mValue - (uint)startPos))
                {
                    continue;
                }

                // constructors (ctors) and destructors (dtors) have multiple types
                // however, clang resolves their addresses to the same function address if there is no need for one of each type
                // so here, we filter them out
                if (mTextFile.ContainsKey(sym.mValue + BaseAdress))
                {
                    continue;
                }

                mAddrToSym.Add(sym.mValue + BaseAdress, symbolName);
                long pos = (long)sym.mValue - startPos;
                byte[] funcBytes = textBytes.Skip((int)pos).Take((int)sym.mSize).ToArray();
                ParseFunction(sym, symbolName, funcBytes, pos, pos + startPos);
            }

            // now those are the functions that we have symbols for
            // let's do the ones that do not have symbols, as they are a bit harder to parse
            // let's first order our dictionary
            mTextFile.OrderByDescending(e => e.Key);

            foreach (ulong offs in mUnknownFuncs)
            {
                var nearest = mTextFile.FirstOrDefault(k => k.Key >= offs);

                if (nearest.Value != null)
                {
                    ulong funcSize = nearest.Key - offs;
                    long pos = (long)offs - startPos;
                    byte[] funcBytes = textBytes.Skip((int)pos).Take((int)funcSize).ToArray();
                }
                else
                {

                }
            }
        }

        private void ParseFunction(DynamicSymbol sym, string symbolName, byte[] funcBytes, long pos, long startOffset)
        {
            List<ulong> jumps = new();
            List<string> funcStr = new();

            using (CapstoneArm64Disassembler dis = CapstoneDisassembler.CreateArm64Disassembler(Arm64DisassembleMode.LittleEndian | Arm64DisassembleMode.Arm))
            {
                dis.EnableInstructionDetails = true;
                // we have to enable this due to the fact that TRAP is invalid with capstone
                dis.EnableSkipDataMode = true;
                dis.DisassembleSyntax = DisassembleSyntax.Intel;

                Arm64Instruction[] instrs = dis.Disassemble(funcBytes, startOffset);
                mFuncInstructions.Add(symbolName, instrs);

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
                    else if (instr.Mnemonic == "bl")
                    {
                        ulong oper = Convert.ToUInt64(instr.Operand.Replace("#", ""), 16);

                        DynamicSymbol? jumpSym = mSymbolTable.GetSymbolAtAddr(oper);

                        string jumpSymName = "";

                        if (jumpSym != null)
                        {
                            jumpSymName = $"bl {mStringTable.GetSymbolAtOffs(jumpSym.mStrTableOffs)}";
                        }
                        else
                        {
                            ulong addr = BaseAdress + oper;
                            if (!mUnknownFuncs.Contains(addr))
                            {
                                mUnknownFuncs.Add(addr);
                            }
                            jumpSymName = $"bl fn_{(BaseAdress + oper).ToString("X")}";
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

                            funcStr.Add($"\t{instr.Mnemonic} #{instr.Details.Operands[1].Immediate} loc_{(BaseAdress + addr).ToString("X")}");
                        }
                        else if (instr.Mnemonic == "cbz")
                        {
                            ulong addr = (ulong)instr.Details.Operands[1].Immediate;

                            if (!jumps.Contains(addr))
                            {
                                jumps.Add(addr);
                            }

                            funcStr.Add($"\t{instr.Mnemonic} loc_{(BaseAdress + addr).ToString("X")}");
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

                                funcStr.Add($"\t{instr.Mnemonic} loc_{(BaseAdress + jmp).ToString("X")}");
                            }
                            else
                            {
                                funcStr.Add($"\t{instr.Mnemonic} fn_{(BaseAdress + jmp).ToString("X")}");
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
                foreach (ulong jmp in jumps)
                {
                    // figure out the offset within the function to insert our instruction at
                    ulong offs = jmp - sym.mValue;
                    // now we get the index into our already obtained list of strings
                    int funcIdx = (int)offs / 4;
                    // insert our local string into the function strings...we use the index + indexof to properly account for other jumps already inserted
                    funcStr.Insert(funcIdx + jumps.IndexOf(jmp), $"loc_{(BaseAdress + jmp).ToString("X")}:");
                }
            }

            mTextFile.Add(BaseAdress + sym.mValue, funcStr);
        }

        public void SaveToFile()
        {
            List<string> file = new();

            foreach (KeyValuePair<ulong, List<string>> e in mTextFile)
            {
                string sym = mAddrToSym[e.Key];
                file.Add($".global {sym}");
                file.Add($"{sym}:");
                foreach (string str in e.Value)
                {
                    file.Add(str);
                }
                file.Add("\n");
            }

            File.WriteAllLines("text.s", file.ToArray());
        }

        public void ExportSectionBinaries()
        {
            File.WriteAllBytes($"{mFileName}_text.bin", mText);
            File.WriteAllBytes($"{mFileName}_data.bin", mData);
            File.WriteAllBytes($"{mFileName}_rodata.bin", mRodata);
        }

        public void PrintInfo()
        {
            Console.WriteLine("============= GENERAL =============");
            string moduleId = "0x" + String.Join("", Array.ConvertAll(mModuleID, value => $"{value:X}"));
            Console.WriteLine($"Module ID: {moduleId}\n");

            Console.WriteLine($"Build String: {mBuildStr.GetBuildStr()}\n");

            string textHash = "0x" + String.Join("", Array.ConvertAll(mTextHash, value => $"{value:X}"));
            string rodataHash = "0x" + String.Join("", Array.ConvertAll(mRoDataHash, value => $"{value:X}"));
            string dataHash = "0x" + String.Join("", Array.ConvertAll(mDataHash, value => $"{value:X}"));

            int maxLabelLength = Math.Max(".text Hash:".Length,
                                    Math.Max(".rodata Hash:".Length, ".data Hash:".Length));

            Console.WriteLine("============= HASHES =============");
            Console.WriteLine($"{".text Hash:".PadRight(maxLabelLength)} {textHash}");
            Console.WriteLine($"{".rodata Hash:".PadRight(maxLabelLength)} {rodataHash}");
            Console.WriteLine($"{".data Hash:".PadRight(maxLabelLength)} {dataHash}\n");

            Console.WriteLine("============= SEGMENTS =============");
            Console.WriteLine($"{"Section".PadRight(12)} | {"Offset".PadRight(12)} | {"Memory Offset".PadRight(16)} | {"Size".PadRight(8)}");
            Console.WriteLine(new string('-', 60));

            Console.WriteLine(
                ".text".PadRight(12) + " | " +
                $"{mTextSegement.GetOffset():X}".PadRight(12) + " | " +
                $"{mTextSegement.GetMemoryOffset():X}".PadRight(16) + " | " +
                $"{mTextSegement.GetSize():X}".PadRight(8)
            );

            Console.WriteLine(
                ".rodata".PadRight(12) + " | " +
                $"{mRodataSegment.GetOffset():X}".PadRight(12) + " | " +
                $"{mRodataSegment.GetMemoryOffset():X}".PadRight(16) + " | " +
                $"{mRodataSegment.GetSize():X}".PadRight(8)
            );

            Console.WriteLine(
                ".data".PadRight(12) + " | " +
                $"{mDataSegment.GetOffset():X}".PadRight(12) + " | " +
                $"{mDataSegment.GetMemoryOffset():X}".PadRight(16) + " | " +
                $"{mDataSegment.GetSize():X}".PadRight(8)
            );
        }
    }
}
