using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace swspl.nso
{
    public enum RelocType
    {
        R_AARCH64_COPY = 1024,
        R_AARCH64_GLOB_DAT = 1025,
        R_AARCH64_JUMP_SLOT = 1026,
        R_AARCH64_RELATIVE = 1027,
        R_AARCH64_TLS_TPREL64 = 1030,
        R_AARCH64_TLS_DTPREL32 = 1031,
        R_AARCH64_IRELATIVE = 1032
    }

    public class RelocationTable
    {
        public RelocationTable(BinaryReader reader, long numRelocs)
        {
            for (int i = 0; i < numRelocs; i++)
            {
                DynamicReloc rl = new(reader);
                mRelocs.Add(rl);
            }
        }

        List<DynamicReloc> mRelocs = new();
    }

    public class DynamicReloc
    {
        public DynamicReloc(BinaryReader reader)
        {
            mOffset = reader.ReadUInt64();
            mInfo = reader.ReadUInt64();
            mAddend = reader.ReadInt64();

            ulong symIdx = mInfo >> 32;
            mRelocType = (RelocType)(mInfo & 0xFFFFFFFF);
        }

        ulong mOffset;
        ulong mInfo;
        long mAddend;
        public RelocType mRelocType;
    }

    public class RelocationPLT 
    {
        public RelocationPLT(BinaryReader reader, long numEntries)
        {
            for (int i = 0; i < numEntries; i++)
            {
                mEntries.Add(new(reader));
            }
        }

        public int GetNumJumps()
        {
            return mEntries.Where(e => e.mRelocType == RelocType.R_AARCH64_JUMP_SLOT).Count();
        }

        List<PLTEntry> mEntries = new();
    }

    public class PLTEntry
    {
        public PLTEntry(BinaryReader reader)
        {
            mOffset = reader.ReadInt64();
            mInfo = reader.ReadInt64();
            mAddend = reader.ReadInt64();

            mRelocType = (RelocType)(mInfo & 0xFFFFFFFF);
        }

        long mOffset;
        long mInfo;
        long mAddend;
        public RelocType mRelocType;
    }

    public class GlobalPLT
    {
        public GlobalPLT(BinaryReader reader, long numAddrs)
        {
            reader.ReadBytes(0x18);
            for (int i = 0; i < numAddrs; i++)
            {
                mAddrs.Add(reader.ReadInt64());
            }
        }

        List<long> mAddrs = new();
    }
}
