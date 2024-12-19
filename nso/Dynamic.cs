using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace swspl.nso
{
    public class DynamicSymbol
    {
        public DynamicSymbol(BinaryReader reader)
        {
            mStrTableOffs = reader.ReadUInt32();
            mInfo = reader.ReadByte();
            mOther = reader.ReadByte();
            mSectionIdx = reader.ReadUInt16();
            mValue = reader.ReadUInt64();
            mSize = reader.ReadUInt64();
        }

        public uint GetTableOffset()
        {
            return mStrTableOffs;
        }

        public uint mStrTableOffs;
        public ulong mValue;
        public ulong mSize;
        public byte mInfo;
        public byte mOther;
        public ushort mSectionIdx;
    }
    public class DynamicSymbolTable
    {
        public DynamicSymbolTable(BinaryReader reader, uint numSyms)
        {
            for (int i = 0; i < numSyms; i++)
            {
                mSymbols.Add(new(reader));
            }
        }

        public List<DynamicSymbol> mSymbols = new();
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

        public static String GetSymbolAtOffs(long offset)
        {
            if (mStringTable.ContainsKey(offset))
            {
                return mStringTable[offset];
            }

            return "UNK";
        }

        static Dictionary<long, String> mStringTable = new();
    }
}
