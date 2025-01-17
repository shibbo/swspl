using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace swspl.nso
{
    public class DynamicSegment
    {
        public enum TagType
        {
            DT_NULL = 0,
            DT_NEEDED = 1,
            DT_PLTRELSZ = 2,
            DT_PLTGOT = 3,
            DT_HASH = 4,
            DT_STRTAB = 5,
            DT_SYMTAB = 6,
            DT_RELA = 7,
            DT_RELASZ = 8,
            DT_RELAENT = 9,
            DT_STRSZ = 10,
            DT_SYMENT = 11,
            DT_INIT = 12,
            DT_FINI = 13,
            DT_SONAME = 14,
            DT_RPATH = 15,
            DT_SYMBOLIC = 16,
            DT_REL = 17,
            DT_RELSZ = 18,
            DT_RELENT = 19,
            DT_PLTREL = 20,
            DT_DEBUG = 21,
            DT_TEXTREL = 22,
            DT_JMPREL = 23,
            DT_BIND_NOW = 24,
            DT_INIT_ARRAY = 25,
            DT_FINI_ARRAY = 26,
            DT_INIT_ARRAYSZ = 27,
            DT_FINI_ARRAYSZ = 28,
            DT_RUNPATH = 29,
            DT_FLAGS = 30,
            DT_ENCODING = 32,
            DT_PREINIT_ARRAY = 32,
            DT_PREINIT_ARRAYSZ = 33,
            DT_NUM = 34,
            DT_LOOS = 0x6000000d,
            DT_HIOS = 0x6ffff000,
            DT_LOPROC = 0x70000000,
            DT_HIPROC = 0x7fffffff,
            DT_ADDRRNGLO = 0x6ffffe00,
            DT_GNU_HASH = 0x6ffffef5,
            DT_TLSDESC_PLT = 0x6ffffef6,
            DT_TLSDESC_GOT = 0x6ffffef7,
            DT_GNU_CONFLICT = 0x6ffffef8,
            DT_GNU_LIBLIST = 0x6ffffef9,
            DT_CONFIG = 0x6ffffefa,
            DT_DEPAUDIT = 0x6ffffefb,
            DT_AUDIT = 0x6ffffefc,
            DT_PLTPAD = 0x6ffffefd,
            DT_MOVETAB = 0x6ffffefe,
            DT_SYMINFO = 0x6ffffeff,
            DT_ADDRRNGHI = 0x6ffffeff,
            DT_RELACOUNT = 0x6ffffff9,
            DT_RELCOUNT = 0x6ffffffa
        }

        public DynamicSegment(BinaryReader reader)
        {
            while (true)
            {
                TagType kind = (TagType)reader.ReadInt64();
                long value = reader.ReadInt64();

                if (kind == 0)
                {
                    break;
                }

                switch (kind)
                {
                    case TagType.DT_NEEDED:
                        if (!mTags.ContainsKey(TagType.DT_NEEDED))
                        {
                            mTags[TagType.DT_NEEDED] = new List<long>();
                            List<long>? values = mTags[TagType.DT_NEEDED] as List<long>;
                            values?.Add(value);
                        }
                        else
                        {
                            List<long>? values = mTags[TagType.DT_NEEDED] as List<long>;
                            values?.Add(value);
                        }
                        break;
                    default:
                        mTags.Add(kind, value);
                        break;
                }
            }
        }

        public bool ContainsTag(TagType type)
        {
            return mTags.ContainsKey(type);
        }

        public T GetTagValue<T>(TagType type)
        {

            return (T)mTags[type];
        }

        public long GetRelocationCount()
        {
            return GetTagValue<long>(TagType.DT_RELASZ) / GetTagValue<long>(TagType.DT_RELAENT);
        }

        

        public Dictionary<TagType, object> mTags = new();
    }

    public class DynamicSymbol
    {
        public enum Bind
        {
            STB_LOCAL = 0,
            STB_GLOBAL = 1,
            STB_WEAK = 2
        }

        public enum Type
        {
            STT_NOTYPE = 0,
            STT_OBJECT = 1,
            STT_FUNC = 2,
            STT_SECTION = 3,
            STT_FILE = 4,
            STT_COMMON = 5,
            STT_TLS = 6
        }

        public enum Vis
        {
            STV_DEFAULT = 0,
            STV_INTERNAL = 1,
            STV_HIDDEN = 2,
            STV_PROTECTED = 3
        }

        public DynamicSymbol(BinaryReader reader)
        {
            if (reader != null)
            {
                mStrTableOffs = reader.ReadUInt32();
                mInfo = reader.ReadByte();
                mOther = reader.ReadByte();
                mSectionIdx = reader.ReadUInt16();
                mValue = reader.ReadUInt64();
                mSize = reader.ReadUInt64();

                mBind = (Bind)(mInfo >> 4);
                mType = (Type)(mInfo & 0xF);
                mVisibility = (Vis)(mOther & 0x3);
            }
        }

        public uint GetTableOffset()
        {
            return mStrTableOffs;
        }

        public Bind GetBind()
        {
            return mBind;
        }

        public Type GetSymType()
        {
            return mType;
        }

        public Vis GetVisibility()
        {
            return mVisibility;
        }

        public ushort GetSectionIdx()
        {
            return mSectionIdx;
        }

        public ulong GetSize()
        {
            return mSize;
        }

        public ulong GetValue()
        {
            return mValue;
        }

        public uint mStrTableOffs;
        public ulong mValue;
        public ulong mSize;
        public byte mInfo;
        public byte mOther;
        public ushort mSectionIdx;
        Bind mBind;
        Type mType;
        Vis mVisibility;
    }
    public class DynamicSymbolTable
    {
        public DynamicSymbolTable(BinaryReader reader, uint numSyms)
        {
            for (int i = 0; i < numSyms; i++)
            {
                mSymbols.Add(new(reader));
            }

            // sort by the address
            mSymbols = mSymbols.OrderBy(symbol => symbol.mValue).ToList();
        }

        public DynamicSymbol? GetSymbolAtAddr(ulong addr)
        {
            int index = mSymbols.BinarySearch(
                new DynamicSymbolStub { mValue = addr },
                Comparer<DynamicSymbol>.Create((a, b) => a.mValue.CompareTo(b.mValue))
            );

            return index >= 0 ? mSymbols[index] : null;
        }

        public List<DynamicSymbol> mSymbols = new();
    }

    public class DynamicSymbolStub : DynamicSymbol
    {
        public DynamicSymbolStub() : base(null!) { }
    }

    public class DynamicStringTable
    {
        public DynamicStringTable(BinaryReader reader, uint dynStrSize)
        {
            long start = reader.BaseStream.Position;
            long end = reader.BaseStream.Position + dynStrSize;

            // always skip byte 1
            reader.ReadByte();

            while (reader.BaseStream.Position < end)
            {
                long offs = reader.BaseStream.Position - start;
                string str = Util.ReadStringNT(reader);
                mStringTable.Add(offs, str);
            }

        }

        public String GetSymbolAtOffs(long offset)
        {
            if (mStringTable.ContainsKey(offset))
            {
                return mStringTable[offset];
            }

            return "UNK";
        }

        public String GetSymbolAtIdx(int idx)
        {
            return mStringTable.Values.ElementAt(idx);
        }

        Dictionary<long, String> mStringTable = new();
    }
}
