using System.Text;
using K4os.Compression.LZ4;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm64;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Linq.Expressions;
using System.Drawing;
using System.Collections.Generic;
using System.Diagnostics.SymbolStore;

namespace swspl.nso
{
    public struct DataRef
    {
        public Arm64RegisterId mRegister;
        public int mIndex;
    }

    public enum DataRefType 
    { 
        BYTE,
        QWORD,
        XWORD,
        SINGLE
    }

    public class NSO
    {
        string mFileName;
        public Dictionary<ulong, List<string>> mTextFile = new();
        public Dictionary<ulong, string> mAddrToSym = new();
        private static readonly ulong BaseAdress = 0x7100000000;
        private DynamicSymbolTable mSymbolTable;
        private DynamicStringTable mStringTable;
        private Dictionary<string, Arm64Instruction[]> mFuncInstructions = new();
        Dictionary<long, DataRefType> mRefTypes = new();

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
        RelocationTable mRelocTable;
        uint mFlags;

        public NSO(string filepath, string map, bool infoOnly)
        {
            mFileName = Path.GetFileNameWithoutExtension(filepath);
            if (File.Exists(filepath))
            {
                Map.LoadMap(map);
                using (BinaryReader reader = new BinaryReader(File.Open(filepath, FileMode.Open), Encoding.UTF8))
                {
                    if (Util.ReadString(reader, 4) != "NSO0")
                    {
                        throw new Exception("NSO::NSO(string) -- Invalid NSO signature.");
                    }

                    string filename = Path.GetFileNameWithoutExtension(filepath);

                    // skip the version and reversed sections
                    reader.ReadBytes(8);

                    Console.WriteLine("Reading header...");

                    mFlags = reader.ReadUInt32();
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

                    Console.WriteLine("Extracting segments...");

                    // now we get the final data for each section
                    // .text
                    reader.BaseStream.Seek(mTextSegement.GetOffset(), SeekOrigin.Begin);
                    // are we compressed?
                    if (IsTextCompr())
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
                    if (IsRodataCompr())
                    {
                        byte[] bytes = reader.ReadBytes(roDataCmprSize);
                        mRodata = new byte[mRodataSegment.GetSize()];
                        LZ4Codec.Decode(bytes, mRodata);
                    }
                    else
                    {
                        mRodata = reader.ReadBytes(mRodataSegment.GetSize());
                    }

                    // .data
                    reader.BaseStream.Seek(mDataSegment.GetOffset(), SeekOrigin.Begin);
                    // are we compressed?
                    if (IsDataCompr())
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
                    BinaryReader dynReader = new(new MemoryStream(mRodata), Encoding.GetEncoding("shift-jis"));

                    Console.WriteLine("Parsing .buildstr...");

                    /* .buildstr */
                    mBuildStr = new(dynReader);

                    Console.WriteLine("Parsing .dymsym...");

                    /* .dynsym */
                    uint numSyms = dynSymSize / 24;
                    dynReader.BaseStream.Seek(dynSymOffs, SeekOrigin.Begin);
                    mSymbolTable = new(dynReader, numSyms);

                    Console.WriteLine("Parsing MOD0...");

                    // MOD0
                    BinaryReader textReader = new(new MemoryStream(mText), Encoding.UTF8);
                    mModule = new(textReader);

                    Console.WriteLine("Parsing .dynamic...");

                    /* .dynamic */
                    uint dynOffs = mModule.mDynOffset - mDataSegment.GetMemoryOffset();
                    BinaryReader dataReader = new(new MemoryStream(mData), Encoding.UTF8);
                    dataReader.BaseStream.Position = dynOffs;
                    mDynamicSegment = new(dataReader);

                    Console.WriteLine("Parsing .hash...");

                    /* .hash */
                    long hashOffs = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_HASH) - mRodataSegment.GetMemoryOffset();
                    dynReader.BaseStream.Seek(hashOffs, SeekOrigin.Begin);
                    mHashTable = new(dynReader);

                    Console.WriteLine("Parsing .gnu_hash...");

                    /* .gnu_hash */
                    mGNUHashTable = new(dynReader);

                    Console.WriteLine("Parsing .rela.dyn...");

                    /* .rela.dyn */
                    long relocCount = mDynamicSegment.GetRelocationCount();
                    long relocOffs = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_RELA) - mRodataSegment.GetMemoryOffset();
                    dynReader.BaseStream.Seek(relocOffs, SeekOrigin.Begin);
                    mRelocTable = new(dynReader, relocCount);

                    Console.WriteLine("Parsing .rela.plt...");

                    /* .rela.plt */
                    long pltOffs = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_JMPREL) - mRodataSegment.GetMemoryOffset();
                    dynReader.BaseStream.Seek(pltOffs, SeekOrigin.Begin);
                    long pltCount = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_PLTRELSZ) / 0x14;
                    RelocationPLT plt = new(dynReader, pltCount);

                    Console.WriteLine("Parsing .dynstr...");

                    /* .dynstr */
                    /* we purposefully read .dynstr last since it is always right before .rodata */
                    dynReader.BaseStream.Seek(dynStrOffs, SeekOrigin.Begin);
                    mStringTable = new(dynReader, dynStrSize);
                    /* align to nearest 0x10th */
                    dynReader.BaseStream.Position = (dynReader.BaseStream.Position + (0x10 - 1)) & ~(0x10 - 1);

                    Console.WriteLine("Parsing .got.plt...");

                    /* .got.plt */
                    long gotPltOffs = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_PLTGOT) - mDataSegment.GetMemoryOffset();
                    GlobalPLT globalPLT = new(dataReader, plt.GetNumJumps());

                    Console.WriteLine("Parsing .got...");

                    /* .got */
                    long gotStart = dataReader.BaseStream.Position;
                    // getting our .got is a bit more difficult
                    // we do not know where it ends, but we do know it is right after .got.plt ends
                    long gotEnd = mDynamicSegment.GetTagValue<long>(DynamicSegment.TagType.DT_INIT_ARRAY) - mDataSegment.GetMemoryOffset();
                    // now let's figure out how many entries we have
                    ulong gotCount = (ulong)(gotEnd - gotStart) / 8;
                    // jump to our memory offset in .got itself to make identifying relocations easier
                    ulong baseAddr = (ulong)(gotStart + mDataSegment.GetMemoryOffset());

                    Console.WriteLine("Exporting .got.plt");

                    List<string> gotPltFile = new();
                    gotPltFile.Add(".section \".got.plt\"\n");
                    long gotPltMemOffs = gotPltOffs + mDataSegment.GetMemoryOffset();
                    int pltIdx = 0;

                    for (int i = 0; i < 3; i++)
                    {
                        ulong o = (ulong)gotPltMemOffs + BaseAdress;
                        gotPltFile.Add($".global off_{o:X}");
                        gotPltFile.Add($"off_{o:X}:");
                        gotPltFile.Add($"\t.quad 0");
                        gotPltMemOffs += 8;
                    }

                    foreach (ulong e in globalPLT.mAddrs)
                    {
                        PLTEntry entr = plt.GetEntryAtIdx(pltIdx);
                        string sym = mStringTable.GetSymbolAtOffs(mSymbolTable.GetSymbolAtIdx((int)entr.mSymIdx).mStrTableOffs);
                        ulong o = (ulong)gotPltMemOffs + BaseAdress;
                        gotPltFile.Add($".global off_{o:X}");
                        gotPltFile.Add($"off_{o:X}:");
                        gotPltFile.Add($"\t.quad {sym}");
                        gotPltMemOffs += 8;
                        pltIdx++;
                    }

                    Console.WriteLine("Exporting .got...");

                    List<string> gotFile = new();
                    gotFile.Add(".section \".got\"\n");

                    for (ulong i = 0; i < gotCount; i++)
                    {
                        ulong addr = baseAddr + (i * 8);
                        gotFile.Add($".global off_{(BaseAdress + addr).ToString("X")}");
                        gotFile.Add($"off_{(BaseAdress + addr).ToString("X")}:");
                        DynamicReloc? reloc = mRelocTable.GetRelocationAtOffset(addr);

                        if (reloc != null)
                        {
                            switch (reloc.mRelocType)
                            {
                                case RelocType.R_AARCH64_RELATIVE:
                                    string addend = ((long)BaseAdress + reloc.GetAddend()).ToString("X");
                                    DynamicSymbol? s = mSymbolTable.GetSymbolAtAddr((ulong)reloc.GetAddend());

                                    if (s != null)
                                    {
                                        gotFile.Add($"\t.quad {mStringTable.GetSymbolAtOffs(s.mStrTableOffs)}");
                                    }
                                    else
                                    {
                                        gotFile.Add($"\t.quad off_{addend}");
                                    }

                                    if (!mRefTypes.ContainsKey((long)BaseAdress + reloc.GetAddend()))
                                    {
                                        mRefTypes.Add((long)BaseAdress + reloc.GetAddend(), DataRefType.QWORD);
                                    }
                                    break;
                                case RelocType.R_AARCH64_GLOB_DAT:
                                case RelocType.R_AARCH64_ABS64:
                                    DynamicSymbol? curSym = mSymbolTable.mSymbols[(int)reloc.GetSymIdx()];
                                    gotFile.Add($"\t.quad {mStringTable.GetSymbolAtOffs(curSym.mStrTableOffs)}");
                                    break;
                            }
                        }
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

                    Console.WriteLine("Exporting .text...");

                    // now we read the remaining portion of .text and map those instructions to symbols
                    int remainingText = mTextSegement.GetSize() - (int)textReader.BaseStream.Position;
                    byte[] textBytes = textReader.ReadBytes(remainingText);
                    ParseTextSegment(textBytes, startPos);

                    mRefTypes = mRefTypes.OrderBy(e => e.Key).ToDictionary();

                    Console.WriteLine("Exporting .bss...");
                    // .bss is a lot of empty data that we can only reference by its usage
                    long bssStart = (long)BaseAdress + mModule.mBssStart;
                    List<string> bssFile = new();
                    bssFile.Add(".section \".bss\"\n");
                    for (uint i = 0; i < bssSize; i++)
                    {
                        if (mRefTypes.ContainsKey(bssStart))
                        {
                            string sym = Map.GetSymbolAtAddr((ulong)bssStart);
                            if (sym != "UNK")
                            {
                                bssFile.Add($".global {sym}");
                                bssFile.Add($"{sym}:");
                            }
                            else
                            {
                                bssFile.Add($".global off_{bssStart:X}");
                                bssFile.Add($"off_{bssStart:X}:");
                            }
                        }

                        bssFile.Add("\t.skip 1");
                        bssStart++;
                    }


                    Console.WriteLine("Exporting .data...");

                    // .dynamic is always after .data in my testing, so we can use that as a reference point to know our data size
                    // the data we are relocating is going to be 8-byte values so we go from there
                    List<string> dataFile = new();
                    dataFile.Add(".section \".data\"\n");

                    ulong dataEntryStart = dynOffs;
                    ulong dataBaseOffs = mDataSegment.GetMemoryOffset();
                    for (ulong i = 0; i < dataEntryStart; i += 8)
                    {
                        ulong addr = dataBaseOffs + i;
                        bool labeled = false;

                        DynamicReloc? reloc = mRelocTable.GetRelocationAtOffset(addr);

                        if (mRefTypes.ContainsKey((long)BaseAdress + (long)addr))
                        {
                            DynamicSymbol? sym = mSymbolTable.GetSymbolAtAddr(addr);

                            if (sym != null)
                            {
                                string s = mStringTable.GetSymbolAtOffs(sym.mStrTableOffs);
                                dataFile.Add($".global {s}");
                                dataFile.Add($"{s}:");
                                labeled = true;
                            }
                            else
                            {
                                dataFile.Add($".global off_{((long)BaseAdress + (long)addr):X}");
                                dataFile.Add($"off_{((long)BaseAdress + (long)addr):X}:");
                                labeled = true;
                            }
                        }

                        if (reloc != null)
                        {
                            DynamicSymbol? sym = mSymbolTable.GetSymbolAtAddr(addr);

                            if (sym != null && labeled == false)
                            {
                                string s = mStringTable.GetSymbolAtOffs(sym.mStrTableOffs);
                                dataFile.Add($".global {s}");
                                dataFile.Add($"{s}:");
                            }

                            /* relative usually points to a function or a set of data */
                            if (reloc.GetRelocType() == RelocType.R_AARCH64_RELATIVE)
                            {
                                // offset to our function
                                DynamicSymbol? refSym = mSymbolTable.GetSymbolAtAddr((ulong)reloc.GetAddend());

                                if (refSym != null)
                                {
                                    string curSym = mStringTable.GetSymbolAtOffs(refSym.mStrTableOffs);
                                    if (labeled == false)
                                    {
                                        dataFile.Add($".global off_{((long)BaseAdress + (long)addr):X}");
                                        dataFile.Add($"off_{((long)BaseAdress + (long)addr):X}:");
                                    }
                                    dataFile.Add($"\t.quad {curSym}");
                                }
                                else
                                {
                                    long offs = (long)BaseAdress + reloc.GetAddend();

                                    // means we found a relocated function only referenced by data with no symbol
                                    // most commonly PTMFs and virtuals
                                    if (mTextSegement.IsInRange((uint)offs))
                                    {
                                        if (labeled == false)
                                        {
                                            dataFile.Add($".global off_{((long)BaseAdress + (long)addr):X}");
                                            dataFile.Add($"off_{((long)BaseAdress + (long)addr):X}:");
                                        }

                                        dataFile.Add($"\t.quad fn_{offs.ToString("X")}");
                                    }
                                    else
                                    {
                                        if (!mRefTypes.ContainsKey(offs))
                                        {
                                            DataRefType t = DataRefType.QWORD;
                                            mRefTypes.Add(offs, t);
                                        }

                                        if (labeled == false)
                                        {
                                            dataFile.Add($".global off_{((long)BaseAdress + (long)addr):X}");
                                            dataFile.Add($"off_{((long)BaseAdress + (long)addr):X}:");
                                        }

                                        dataFile.Add($"\t.quad off_{offs.ToString("X")}");
                                    }
                                }
                            }
                            /* absolute or glob uses addends */
                            else if (reloc.GetRelocType() == RelocType.R_AARCH64_ABS64 || reloc.GetRelocType() == RelocType.R_AARCH64_GLOB_DAT)
                            {
                                DynamicSymbol? refSym = mSymbolTable.GetSymbolAtIdx((int)reloc.GetSymIdx());
                                string curSym = mStringTable.GetSymbolAtOffs(refSym.mStrTableOffs);
                                if (labeled == false)
                                {
                                    dataFile.Add($".global off_{((long)BaseAdress + (long)addr):X}");
                                    dataFile.Add($"off_{((long)BaseAdress + (long)addr):X}:");
                                }
                                dataFile.Add($"\t.quad {curSym}");
                            }
                        }
                        else
                        {
                            long a = (long)BaseAdress + (long)addr;
                            if (labeled == false)
                            {
                                dataFile.Add($".global off_{a:X}");
                                dataFile.Add($"off_{a:X}:");
                            }

                            if (mRefTypes.ContainsKey(a))
                            {
                                DataRefType t = mRefTypes[(long)a];
                                if (t == DataRefType.BYTE)
                                {
                                    byte[] val = new byte[1];
                                    Array.Copy(mData, (int)i, val, 0, 1);
                                    int l = val[0];
                                    dataFile.Add($"\t.byte 0x{l:X}");

                                    for (int j = 0; j < 3; j++)
                                    {
                                        dataFile.Add($"\t.byte 0");
                                    }
                                }
                                else if (t == DataRefType.QWORD)
                                {
                                    byte[] val = new byte[8];
                                    Array.Copy(mData, (int)i, val, 0, 8);
                                    long l = BitConverter.ToInt64(val);
                                    dataFile.Add($"\t.quad 0x{l:X}");
                                }
                                else if (t == DataRefType.SINGLE)
                                {
                                    byte[] val = new byte[4];
                                    Array.Copy(mData, (int)i, val, 0, 4);
                                    float l = BitConverter.ToSingle(val);
                                    dataFile.Add($"\t.float {l}");
                                }
                                else
                                {
                                    Console.WriteLine($"unsupported data ref type alert: {t}");
                                }
                            }
                            else
                            {
                                byte[] val = new byte[8];
                                Array.Copy(mData, (int)i, val, 0, 8);
                                long l = BitConverter.ToInt64(val);
                                dataFile.Add($"\t.quad 0x{l:X}");
                            }
                        }
                    }

                    mRefTypes = mRefTypes.OrderBy(e => e.Key).ToDictionary();

                    Console.WriteLine("Exporting .rodata...");

                    /* .rodata */
                    long size = embedOffs - dynReader.BaseStream.Position;
                    List<string> rodataFile = new();
                    bool hasAlignedForFloat = false;
                    bool hasAlignedForData = false;
                    rodataFile.Add(".section \".rodata\"\n");

                    ulong rodataBaseOffs = mRodataSegment.GetMemoryOffset() + (ulong)dynReader.BaseStream.Position;

                    for (ulong i = 0; i < (ulong)size; ) 
                    {
                        ulong addr = rodataBaseOffs + i;
                        ulong a = BaseAdress + addr;

                        if (mRefTypes.ContainsKey((long)a))
                        {
                            long? nextKey = mRefTypes.Keys.FirstOrDefault(key => key > (long)a);
                            long dist = (long)nextKey - (long)a;
                            DataRefType t = mRefTypes[(long)a];

                            if (t == DataRefType.QWORD)
                            {
                                byte[] b = dynReader.ReadBytes((int)dist);
                                string s = Encoding.UTF8.GetString(b);

                                if (Util.IsValidUtf8(b))
                                {
                                    b = Util.TrimNullTerminator(b);
                                    s = Encoding.UTF8.GetString(b);

                                    rodataFile.Add($".global off_{a:X}");
                                    rodataFile.Add($"off_{a:X}:");
                                    s = s.Replace("\t", "\\t")
                                        .Replace("\\", "\\\\")
                                        .Replace("\"", "\\\"")
                                        .Replace("\r", "\\r")
                                        .Replace("\n", "\\n");
                                    rodataFile.Add($"\t.string \"{s}\"");
                                    rodataFile.Add("\t.byte 0");
                                }
                                else
                                {
                                    rodataFile.Add($".global off_{a:X}");
                                    rodataFile.Add($"off_{a:X}:");
                                    for (long j = 0; j < dist; j++)
                                    {
                                        rodataFile.Add($"\t.byte 0x{b[j]:X}");
                                    }
                                }

                                i += (ulong)dist;
                            }
                            else if (t == DataRefType.SINGLE)
                            {
                                /* the first float entry gets aligned since this ends the string data */
                                if (!hasAlignedForFloat)
                                {
                                    rodataFile.Add($"\t.align 0x10");
                                    /* align to nearest 0x10th */
                                    i = (i + (0x10Ul - 10Ul)) & ~(0x10Ul - 10Ul);
                                    hasAlignedForFloat = true;
                                }
                                byte[] val = dynReader.ReadBytes(4);
                                string s;

                                if (val[0] == 0x00 && val[1] == 0x00 && val[2] == 0x80 && val[3] == 0xFF)
                                {
                                    s = "-Inf";
                                }
                                else if (val[0] == 0x00  && val[1] == 0x00 && val[2] == 0x80 && val[3] == 0x7F) {
                                    s = "Inf";
                                }
                                else
                                {
                                    float l = BitConverter.ToSingle(val);
                                    // clang doesn't like the default string representation of exponent floats
                                    s = l.ToString("G");
                                    if (s.Contains("E"))
                                    {
                                        s = l.ToString("0.0E+0");
                                    }
                                    else
                                    {
                                        s = l.ToString("0.0");
                                    }
                                }

                                rodataFile.Add($".global off_{a:X}");
                                rodataFile.Add($"off_{a:X}:");
                                rodataFile.Add($"\t.float {s}");
                                i += 4;
                            }
                            else if (t == DataRefType.XWORD)
                            {
                                if (!hasAlignedForData)
                                {
                                    rodataFile.Add($"\t.align 0x10");
                                    /* align to nearest 0x10th */
                                    i = (i + (0x10Ul - 10Ul)) & ~(0x10Ul - 10Ul);
                                    hasAlignedForData = true;
                                }

                                rodataFile.Add($".global off_{a:X}");
                                rodataFile.Add($"off_{a:X}:");

                                for (long j = 0; j < 16; j++)
                                {
                                    byte b = dynReader.ReadByte();
                                    rodataFile.Add($"\t.byte 0x{b:X}");
                                }

                                i += 16;
                            }
                            else if (t == DataRefType.BYTE)
                            {
                                rodataFile.Add($".global off_{a:X}");
                                rodataFile.Add($"off_{a:X}:");
                                byte b = dynReader.ReadByte();
                                rodataFile.Add($"\t.byte 0x{b:X}");

                                for (long j = 0; j < 3; j++)
                                {
                                    rodataFile.Add($"\t.byte 0");
                                }

                                i += 4;
                            }
                        }
                        else
                        {
                            byte b = dynReader.ReadByte();
                            rodataFile.Add($"\t.byte 0x{b:X}");
                            i++;
                        }
                    }

                    /* if we are only dumping info, we can stop here. */
                    if (infoOnly)
                    {
                        return;
                    }

                    Console.WriteLine("Writing to files...");

                    Directory.CreateDirectory($"{mFileName}\\asm");
                    File.WriteAllLines($"{mFileName}\\asm\\got.s", gotFile.ToArray());
                    File.WriteAllLines($"{mFileName}\\asm\\got.plt.s", gotPltFile.ToArray());
                    File.WriteAllLines($"{mFileName}\\asm\\data.s", dataFile.ToArray());
                    File.WriteAllLines($"{mFileName}\\asm\\rodata.s", rodataFile.ToArray());
                    File.WriteAllLines($"{mFileName}\\asm\\bss.s", bssFile.ToArray());
                }
            }
            else
            {
                throw new Exception("NSO::NSO(string) -- File does not exist.");
            }
        }

        private bool IsTextCompr()
        {
            return (mFlags & 0x1) != 0;
        }

        private bool IsRodataCompr()
        {
            return ((mFlags >> 1) & 0x1) != 0;
        }

        private bool IsDataCompr()
        {
            return ((mFlags >> 2) & 0x1) != 0;
        }

        public void ParseTextSegment(byte[] textBytes, long startPos)
        {
            foreach(string key in Map.mSymbols.Keys)
            {
                Map.Symbol symbol = Map.mSymbols[key];
                AssignAddrToSym(symbol.GetAddr(), key);
                long pos = (long)(symbol.GetAddr() - BaseAdress) - startPos;
                byte[] funcBytes = textBytes.Skip((int)pos).Take((int)symbol.GetSize()).ToArray();
                ParseFunction((ulong)symbol.GetSize(), symbol.GetAddr() - BaseAdress, key, funcBytes, pos, pos + startPos);
            }

            mTextFile = mTextFile.OrderBy(e => e.Key).ToDictionary();
            mAddrToSym = mAddrToSym.OrderBy(e => e.Key).ToDictionary();
        }

        private void ParseFunction(ulong size, ulong symAddr, string symbolName, byte[] funcBytes, long pos, long startOffset)
        {
            List<ulong> jumps = new();
            List<string> funcStr = new();
            Dictionary<long, List<DataRef>> dataRefIndicies = new();

            using (CapstoneArm64Disassembler dis = CapstoneDisassembler.CreateArm64Disassembler(Arm64DisassembleMode.LittleEndian | Arm64DisassembleMode.Arm))
            {
                dis.EnableInstructionDetails = true;
                // we have to enable this due to the fact that TRAP is invalid with capstone
                dis.EnableSkipDataMode = true;
                dis.DisassembleSyntax = DisassembleSyntax.Intel;

                Arm64Instruction[] instrs = dis.Disassemble(funcBytes, startOffset);
                mFuncInstructions.Add(symbolName, instrs);

                Dictionary<Arm64RegisterId, long> dataRegVals = new();

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
                        else if (instr.Operand == "0x00, 0x00, 0x00, 0x00")
                        {
                            funcStr.Add($".fill 4, 1, 0");
                        }
                    }
                    // bl need to be defined differently
                    else if (instr.Mnemonic == "bl")
                    {
                        ulong oper = Convert.ToUInt64(instr.Operand.Replace("#", ""), 16);
                        string sym = Map.GetSymbolAtAddr(BaseAdress + oper);
                        funcStr.Add($"\tbl {sym}");
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

                            funcStr.Add($"\t{instr.Mnemonic} {instr.Details.Operands[0].Register.Name}, #{instr.Details.Operands[1].Immediate}, loc_{(BaseAdress + addr).ToString("X")}");
                        }
                        else if (instr.Mnemonic == "cbz")
                        {
                            string reg = instr.Details.Operands[0].Register.Name;
                            ulong addr = (ulong)instr.Details.Operands[1].Immediate;

                            if (!jumps.Contains(addr))
                            {
                                jumps.Add(addr);
                            }

                            funcStr.Add($"\t{instr.Mnemonic} {reg}, loc_{(BaseAdress + addr).ToString("X")}");
                        }
                        else if (instr.Mnemonic == "cbnz")
                        {
                            string reg = instr.Details.Operands[0].Register.Name;
                            ulong addr = (ulong)instr.Details.Operands[1].Immediate;

                            if (!jumps.Contains(addr))
                            {
                                jumps.Add(addr);
                            }

                            funcStr.Add($"\t{instr.Mnemonic} {reg}, loc_{(BaseAdress + addr).ToString("X")}");
                        }
                        else if (Util.IsLocalBranchInstr(instr.Mnemonic)) 
                        {
                            ulong jmp = Convert.ToUInt64(instr.Operand.Replace("#", ""), 16);

                            if (!jumps.Contains(jmp))
                            {
                                jumps.Add(jmp);
                            }

                            funcStr.Add($"\t{instr.Mnemonic} loc_{(BaseAdress + jmp).ToString("X")}");
                        }
                        else
                        {
                            // sometimes the compiler can branch to another function without using BL
                            // make sure we account for it
                            ulong jmp = Convert.ToUInt64(instr.Operand.Replace("#", ""), 16);

                            ulong range = size + (ulong)startOffset;
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

                                funcStr.Add($"\t{instr.Mnemonic} loc_{(BaseAdress + jmp):X}");
                            }
                            else
                            {
                                string sym = Map.GetSymbolAtAddr(BaseAdress + jmp);
                                funcStr.Add($"\t{instr.Mnemonic} {sym}");
                                
                            }
                        }

                    }
                    else if (instr.Mnemonic == "adrp")
                    {
                        long dataAddr = instr.Details.Operands[1].Immediate;
                        Arm64RegisterId reg = instr.Details.Operands[0].Register.Id;

                        if (!dataRegVals.ContainsKey(reg))
                        {
                            dataRegVals.Add(reg, (long)BaseAdress + dataAddr);
                        }

                        funcStr.Add($"\tadrp {instr.Details.Operands[0].Register.Name}, off_REPLACEME");
                        DataRef r = new();
                        r.mRegister = reg;
                        r.mIndex = funcStr.Count - 1;

                        if (dataRefIndicies.ContainsKey((long)BaseAdress + dataAddr))
                        {
                            dataRefIndicies[(long)BaseAdress + dataAddr].Add(r);
                        }
                        else
                        {
                            dataRefIndicies[(long)BaseAdress + dataAddr] = new();
                            dataRefIndicies[(long)BaseAdress + dataAddr].Add(r);
                        }
                    }
                    else if (instr.Mnemonic == "adr")
                    {
                        ulong dataAddr = (ulong)instr.Details.Operands[1].Immediate;

                        if (!jumps.Contains(dataAddr))
                        {
                            jumps.Add(dataAddr);
                        }

                        funcStr.Add($"\t{instr.Mnemonic} {instr.Details.Operands[0].Register.Name}, loc_{(BaseAdress + dataAddr).ToString("X")}");
                    }
                    else if (instr.Mnemonic == "add")
                    {
                        Arm64RegisterId srcReg = instr.Details.Operands[1].Register.Id;

                        if (dataRegVals.ContainsKey(srcReg))
                        {
                            string srcReg_Str = instr.Details.Operands[1].Register.Name;
                            string destReg_Str = instr.Details.Operands[0].Register.Name;
                            long finalAddr = dataRegVals[srcReg] + instr.Details.Operands[2].Immediate;
                            List<DataRef> r = dataRefIndicies[dataRegVals[srcReg]];
                            int idx = -1;
                            int refIdx = 0;

                            foreach (DataRef _ in r)
                            {
                                if (_.mRegister == srcReg)
                                {
                                    idx = _.mIndex;
                                    break;
                                }

                                refIdx++;
                            }

                            if (!mRefTypes.ContainsKey(finalAddr))
                            {
                                DataRefType t = DataRefType.QWORD;
                                if (destReg_Str.StartsWith("s"))
                                {
                                    t = DataRefType.SINGLE;
                                }
                                else if (destReg_Str.StartsWith("q"))
                                {
                                    t = DataRefType.XWORD;
                                }

                                mRefTypes.Add(finalAddr, t);
                            }

                            dataRefIndicies[dataRegVals[srcReg]].RemoveAt(refIdx);

                            if (Map.IsInText((ulong)finalAddr))
                            {
                                string sym = Map.GetSymbolAtAddr((ulong)finalAddr);

                                if (sym != "UNK")
                                {
                                    funcStr.Add($"\tadd {destReg_Str}, {srcReg_Str}, :lo12:{sym}");

                                    string ff = funcStr.ElementAt(idx);
                                    ff = ff.Replace("off_REPLACEME", $"{sym}");
                                    funcStr[idx] = ff;
                                    dataRegVals.Remove(srcReg);
                                    continue;
                                }
                            }

                            string f = funcStr.ElementAt(idx);
                            f = f.Replace("REPLACEME", $"{finalAddr:X}");
                            funcStr[idx] = f;
                            dataRegVals.Remove(srcReg);
                            funcStr.Add($"\tadd {destReg_Str}, {srcReg_Str}, :lo12:off_{finalAddr:X}");
                        }
                        else
                        {
                            // we don't do anything to the add if it's just a normal add
                            funcStr.Add($"\t{instr}");
                        }
                    }
                    else if (instr.Mnemonic == "ldr" || instr.Mnemonic == "str")
                    {
                        Arm64RegisterId srcReg = instr.Details.Operands[1].Memory.Base.Id;

                        if (dataRegVals.ContainsKey(srcReg))
                        {
                            string dstReg_Str = instr.Details.Operands[0].Register.Name;
                            string srcReg_Str = instr.Details.Operands[1].Memory.Base.Name;
                            long destAddr = instr.Details.Operands[1].Memory.Displacement;
                            if (instr.Mnemonic == "ldr")
                            {
                                funcStr.Add($"\tldr {dstReg_Str}, [{srcReg_Str}, :lo12:off_{(dataRegVals[srcReg] + destAddr):X}]");
                            }
                            else
                            {
                                funcStr.Add($"\tstr {dstReg_Str}, [{srcReg_Str}, :lo12:off_{(dataRegVals[srcReg] + destAddr):X}]");
                            }

                            // now let's adjust our other loader (adrp)
                            List<DataRef> r = dataRefIndicies[dataRegVals[srcReg]];
                            int idx = -1;
                            int refIdx = 0;

                            foreach (DataRef _ in r)
                            {
                                if (_.mRegister == srcReg)
                                {
                                    idx = _.mIndex;
                                    break;
                                }

                                refIdx++;
                            }

                            long a = dataRegVals[srcReg] + destAddr;
                            if (!mRefTypes.ContainsKey(a))
                            {
                                DataRefType t = DataRefType.QWORD;
                                if (dstReg_Str.StartsWith("s"))
                                {
                                    t = DataRefType.SINGLE;
                                }
                                else if (dstReg_Str.StartsWith("q"))
                                {
                                    t = DataRefType.XWORD;
                                }

                                mRefTypes.Add(dataRegVals[srcReg] + destAddr, t);
                            }

                            dataRefIndicies[dataRegVals[srcReg]].RemoveAt(refIdx);
                            string f = funcStr.ElementAt(idx);
                            f = f.Replace("REPLACEME", $"{(dataRegVals[srcReg] + destAddr):X}");
                            funcStr[idx] = f;
                            dataRegVals.Remove(srcReg);

                        }
                        else
                        {
                            // we don't do anything to the ldr if it's just a normal load
                            funcStr.Add($"\t{instr}");
                        }
                    }
                    else if (instr.Mnemonic == "ldrb" || instr.Mnemonic == "strb")
                    {
                        Arm64RegisterId srcReg = instr.Details.Operands[1].Memory.Base.Id;

                        if (dataRegVals.ContainsKey(srcReg))
                        {
                            string dstReg_Str = instr.Details.Operands[0].Register.Name;
                            string srcReg_Str = instr.Details.Operands[1].Memory.Base.Name;
                            long destAddr = instr.Details.Operands[1].Memory.Displacement;
                            if (instr.Mnemonic == "ldrb")
                            {
                                funcStr.Add($"\tldrb {dstReg_Str}, [{srcReg_Str}, :lo12:off_{(dataRegVals[srcReg] + destAddr):X}]");
                            }
                            else
                            {
                                funcStr.Add($"\tstrb {dstReg_Str}, [{srcReg_Str}, :lo12:off_{(dataRegVals[srcReg] + destAddr):X}]");
                            }
                            

                            // now let's adjust our other loader (adrp)
                            List<DataRef> r = dataRefIndicies[dataRegVals[srcReg]];
                            int idx = -1;
                            int refIdx = 0;

                            foreach (DataRef _ in r)
                            {
                                if (_.mRegister == srcReg)
                                {
                                    idx = _.mIndex;
                                    break;
                                }

                                refIdx++;
                            }

                            long a = dataRegVals[srcReg] + destAddr;
                            if (!mRefTypes.ContainsKey(a))
                            {
                                mRefTypes.Add(a, DataRefType.BYTE);
                            }

                            dataRefIndicies[dataRegVals[srcReg]].RemoveAt(refIdx);

                            string f = funcStr.ElementAt(idx);
                            f = f.Replace("REPLACEME", $"{(dataRegVals[srcReg] + destAddr):X}");
                            funcStr[idx] = f;
                            dataRegVals.Remove(srcReg);

                        }
                        else
                        {
                            funcStr.Add($"\t{instr}");
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
                    ulong offs = jmp - symAddr;
                    // now we get the index into our already obtained list of strings
                    int funcIdx = (int)offs / 4;
                    // insert our local string into the function strings...we use the index + indexof to properly account for other jumps already inserted
                    funcStr.Insert(funcIdx + jumps.IndexOf(jmp), $"loc_{(BaseAdress + jmp).ToString("X")}:");
                }
            }
                
            mTextFile.Add(BaseAdress + symAddr, funcStr);
        }

        public void AssignAddrToSym(ulong addr, string name)
        {
            if (!mAddrToSym.ContainsKey(addr))
            {
                mAddrToSym.Add(addr, name);
            }
            else
            {
                mAddrToSym[addr] = name;
            }
        }

        public void SaveToFile()
        {
            List<string> file = new();

            foreach (KeyValuePair<ulong, List<string>> e in mTextFile)
            {
                string sym = mAddrToSym[e.Key];

                ulong? above = Util.FindClosestKeyAboveNEq((long)e.Key, mTextFile.Keys);
                ulong dist = 0;

                if (above != null)
                {
                    dist = (ulong)above - (e.Key + (ulong)Map.GetSymbolSize(sym));
                }

                file.Add($"# 0x{e.Key:X} | 0x{(ulong)Map.GetSymbolSize(sym):X}");
                file.Add($".global {sym}");
                file.Add($"{sym}:");
                foreach (string str in e.Value)
                {
                    file.Add(str);
                }

                if (dist != 0)
                {
                    file.Add($".fill {dist}, 1, 0");
                }

                file.Add("\n");
            }

            Directory.CreateDirectory($"{mFileName}\\asm");
            File.WriteAllLines($"{mFileName}\\asm\\text.s", file.ToArray());
            ExportSectionBinaries();
        }

        public void ExportSectionBinaries()
        {
            Directory.CreateDirectory($"{mFileName}\\bin");
            File.WriteAllBytes($"{mFileName}\\bin\\text.bin", mText);
            File.WriteAllBytes($"{mFileName}\\bin\\data.bin", mData);
            File.WriteAllBytes($"{mFileName}\\bin\\rodata.bin", mRodata);
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
            Console.WriteLine($"{"Section".PadRight(12)} | {"Offset".PadRight(12)} | {"Memory Offset".PadRight(16)} | {"Size".PadRight(8)} | {"Compressed?".PadRight(12)}");
            Console.WriteLine(new string('-', 72));

            Console.WriteLine(
                ".text".PadRight(12) + " | " +
                $"{mTextSegement.GetOffset():X}".PadRight(12) + " | " +
                $"{mTextSegement.GetMemoryOffset():X}".PadRight(16) + " | " +
                $"{mTextSegement.GetSize():X}".PadRight(8) + " | " +
                $"{IsTextCompr()}"

            );

            Console.WriteLine(
                ".rodata".PadRight(12) + " | " +
                $"{mRodataSegment.GetOffset():X}".PadRight(12) + " | " +
                $"{mRodataSegment.GetMemoryOffset():X}".PadRight(16) + " | " +
                $"{mRodataSegment.GetSize():X}".PadRight(8) + " | " +
                $"{IsRodataCompr()}"
            );

            Console.WriteLine(
                ".data".PadRight(12) + " | " +
                $"{mDataSegment.GetOffset():X}".PadRight(12) + " | " +
                $"{mDataSegment.GetMemoryOffset():X}".PadRight(16) + " | " +
                $"{mDataSegment.GetSize():X}".PadRight(8) + " | " +
                $"{IsDataCompr()}\n"
            );

            Console.WriteLine("============= DYNAMIC =============");
            Console.WriteLine($"{"Tag".PadRight(24)} | {"Value".PadRight(24)}");
            Console.WriteLine(new string('-', 48));

            foreach(KeyValuePair<DynamicSegment.TagType, object> kvp in mDynamicSegment.mTags)
            {
                string? val = "";
                if (kvp.Key == DynamicSegment.TagType.DT_NEEDED)
                {
                    var neededArr = kvp.Value as List<long>;

                    if (neededArr != null)
                    {
                        val = "[";

                        for (int i = 0; i < neededArr.Count; i++)
                        {
                            val += $" {neededArr[i].ToString("X")} ";
                        }

                        val += "]";
                    }
                }
                else
                {
                    if (kvp.Value is long)
                    {
                        long v = (long)kvp.Value;
                        val = "0x" + v.ToString("X");
                    }
                    else
                    {
                        val = kvp.Value.ToString();
                    }
                    
                }

                if (val != null)
                {
                    Console.WriteLine(
                        $"{kvp.Key.ToString().PadRight(24)} | " +
                        $"{val.PadRight(24)}"
                    );
                }                
            }
            Console.WriteLine("\n");

            Console.WriteLine("============= .rela.dyn =============");
            Console.WriteLine($".rela.dyn contains {mRelocTable.mRelocs.Count} entries.\n");

            Console.WriteLine($"{"Offset".PadRight(12)} | {"Info".PadRight(12)} | {"Type".PadRight(16)} | {"Value".PadRight(8)} | {"Sym Name + Addend".PadRight(12)}");
            Console.WriteLine(new string('-', 84));

            foreach (DynamicReloc reloc in mRelocTable.mRelocs)
            {
                string symVal = "";
                string addend = $"0x{reloc.GetAddend()}";
                if (reloc.GetRelocType() == RelocType.R_AARCH64_RELATIVE)
                {
                    symVal = "             ";
                }
                else if (reloc.GetRelocType() == RelocType.R_AARCH64_ABS64 || reloc.GetRelocType() == RelocType.R_AARCH64_GLOB_DAT)
                {
                    var sym = mSymbolTable.mSymbols[(int)reloc.GetSymIdx()];
                    string symb = mStringTable.GetSymbolAtOffs(sym.mStrTableOffs);
                    addend = $"{symb} + {reloc.GetAddend().ToString("X")}";
                }
                else 
                {
                    symVal = reloc.GetSymIdx().ToString("X");
                }

                Console.WriteLine(
                    $"0x{reloc.GetOffset().ToString("X")}".PadRight(12) + " | " +
                    $"0x{reloc.GetInfo().ToString("X")}".PadRight(12) + " | " +
                    $"{reloc.GetRelocType()}".PadRight(16) + " | " +
                    $"{symVal}".PadRight(12) + " | " +
                    $"{addend}".PadRight(12)
                );
            }

            Console.WriteLine("\n");

            Console.WriteLine("============= .dynsym =============");

            Console.WriteLine($"{"Num".PadRight(4)} | {"Value".PadRight(12)} | {"Size".PadRight(8)} | {"Type".PadRight(8)} | {"Bind".PadRight(8)} | {"Vis".PadRight(8)} | {"Ndx".PadRight(2)} | {"Name".PadRight(8)}");
            Console.WriteLine(new string('-', 120));

            foreach (DynamicSymbol sym in mSymbolTable.mSymbols)
            {
                string symName = mStringTable.GetSymbolAtOffs((int)sym.mStrTableOffs);

                string sectionIdx = sym.GetSectionIdx().ToString();

                if (sym.mSectionIdx == 0)
                {
                    sectionIdx = "UND";
                }

                Console.WriteLine(
                    $"{mSymbolTable.mSymbols.IndexOf(sym)}:".PadRight(4) + " | " +
                    $"{sym.GetValue()}".PadRight(12) + " | " +
                    $"{sym.GetSize()}".PadRight(8) + " | " +
                    $"{sym.GetSymType()}".PadRight(8) + " | " +
                    $"{sym.GetBind()}".PadRight(8) + " | " +
                    $"{sym.GetVisibility()}".PadRight(8) + " | " +
                    $"{sectionIdx}".PadRight(2) + " | " +
                    $"{symName}".PadRight(8)
                );
            }
        }
    }
}
