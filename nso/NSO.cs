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

                    //File.WriteAllBytes("text.bin", text);
                    //File.WriteAllBytes("rodata.bin", rodata);

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
                    // our build string is right at the beginning
                    BuildStr buildStr = new(dynReader);
                    dynReader.BaseStream.Seek(dynStrOffs, SeekOrigin.Begin);
                    DynamicStringTable strTbl = new(dynReader, dynStrSize);
                    uint numSyms = dynSymSize / 24;
                    dynReader.BaseStream.Seek(dynSymOffs, SeekOrigin.Begin);
                    DynamicSymbolTable dynTbl = new(dynReader, numSyms);


                    //File.WriteAllBytes("data.bin", data);

                    // our module info and other stuff is inside of .text
                    BinaryReader textReader = new(new MemoryStream(text), Encoding.UTF8);
                    Module module = new(textReader);

                    // now let's find our .dynamic section, as it is a bit tricky
                    uint dynOffs = module.mDynOffset - dataSeg.GetMemoryOffset();
                    // our .dynamic section is in .data
                    BinaryReader dataReader = new(new MemoryStream(data), Encoding.UTF8);
                    dataReader.BaseStream.Position = dynOffs;
                    DynamicSegment seg = new(dataReader);

                    // .hash is in our rodata
                    // we access its offset in the .rodata binary
                    long hashOffs = seg.GetTagValue<long>(DynamicSegment.TagType.DT_HASH) - rodataSeg.GetMemoryOffset();
                    dynReader.BaseStream.Seek(hashOffs, SeekOrigin.Begin);
                    HashTable hashTbl = new(dynReader);
                    GNUHashTable gnuHashTbl = new(dynReader);

                    long relocCount = seg.GetRelocationCount();
                    // jump to our relocation table
                    long relocOffs = seg.GetTagValue<long>(DynamicSegment.TagType.DT_RELA) - rodataSeg.GetMemoryOffset();
                    dynReader.BaseStream.Seek(relocOffs, SeekOrigin.Begin);
                    RelocationTable relocTbl = new(dynReader, relocCount);
                    long pltOffs = seg.GetTagValue<long>(DynamicSegment.TagType.DT_JMPREL) - rodataSeg.GetMemoryOffset();
                    dynReader.BaseStream.Seek(pltOffs, SeekOrigin.Begin);
                    long pltCount = seg.GetTagValue<long>(DynamicSegment.TagType.DT_PLTRELSZ) / 0x14;
                    RelocationPLT plt = new(dynReader, pltCount);
                    long gotPltOffs = seg.GetTagValue<long>(DynamicSegment.TagType.DT_PLTGOT) - dataSeg.GetMemoryOffset();
                    GlobalPLT globalPLT = new(dataReader, plt.GetNumJumps());
                    List<string> syms = new();

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

                    // let's see if we can build a symbols.txt
                    for (int i = 0; i < numSyms; i++)
                    {
                        DynamicSymbol sym = dynTbl.mSymbols[i];
                        string symbol = DynamicStringTable.GetSymbolAtOffs(sym.mStrTableOffs);

                        string section;

                        if (symbol == "dialog_arc_org_size")
                        {

                        }

                        switch (sym.mSectionIdx)
                        {
                            case 0:
                            case 2:
                                section = ".text";
                                break;
                            case 1:
                                section = ".rodata";
                                break;
                            case 11:
                                section = ".rodata.2";
                                break;
                            case 17:
                                section = ".data";
                                break;
                            case 26:
                                section = ".bss";
                                break;
                            default:
                                section = ".unk";
                                break;
                        }

                        string binding;
                        switch (sym.mInfo >> 4)
                        {
                            case 0:
                                binding = "scope:local";
                                break;
                            case 1:
                                binding = "scope:global";
                                break;
                            case 2:
                                binding = "scope:weak";
                                break;
                            default:
                                binding = "scope:unknown";
                                break;
                        }

                        string type;
                        switch (sym.mInfo & 0xF)
                        {
                            case 1:
                                type = "type:object";
                                break;
                            case 2:
                                type = "type:function";
                                break;
                            case 3:
                                type = "type:section";
                                break;
                            case 4:
                                type = "type:file";
                                break;
                            default:
                                type = "type:unknown";
                                break;
                        }

                        if (sym.mSize == 0)
                        {
                            continue;
                        }

                        string size = $"{sym.mSize:X}".TrimStart('0').Insert(0, "0x");
                        syms.Add($"{symbol} = {section}:0x{sym.mValue:X8}; // {type} size:{size} {binding}");
                    }

                    //File.WriteAllLines("symbols.txt", syms);
                    
                }
            }
            else
            {
                throw new Exception("NSO::NSO(string) -- File does not exist.");
            }
        }
    }
}
