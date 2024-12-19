using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using K4os.Compression.LZ4;
using System.Security.Cryptography;

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

                    // now let's check our hashes to ensuraaaaaaaaaaaae we have the right data
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
                    dynReader.BaseStream.Seek(dynStrOffs, SeekOrigin.Begin);
                    DynamicStringTable strTbl = new(dynReader, dynStrSize);
                    uint numSyms = dynSymSize / 24;
                    dynReader.BaseStream.Seek(dynSymOffs, SeekOrigin.Begin);
                    DynamicSymbolTable dynTbl = new(dynReader, numSyms);

                    // let's see if we can build a symbols.txt
                    for (int i = 0; i < numSyms; i++)
                    {
                        DynamicSymbol sym = dynTbl.mSymbols[i];
                        string symbol = DynamicStringTable.GetSymbolAtOffs(sym.mStrTableOffs);

                        string binding;
                        switch (sym.mInfo >> 4)
                        {
                            case 0:
                                binding = "LOCAL";
                                break;
                            case 1:
                                binding = "GLOBAL";
                                break;
                            case 2:
                                binding = "WEAK";
                                break;
                            default:
                                binding = "UNK";
                                break;
                        }

                        string type;
                        switch (sym.mInfo & 0xF)
                        {
                            case 1:
                                type = "OBJECT";
                                break;
                            case 2:
                                type = "FUNC";
                                break;
                            case 3:
                                type = "SECTION";
                                break;
                            case 4:
                                type = "FILE";
                                break;
                            default:
                                type = "UNK";
                                break;
                        }

                        Console.WriteLine($"Address: {sym.mValue}\tSize: {sym.mSize}\tType: {type}\tBinding: {binding}\tSymbol: {symbol}");
                    }
                    
                }
            }
            else
            {
                throw new Exception("NSO::NSO(string) -- File does not exist.");
            }
        }
    }
}
