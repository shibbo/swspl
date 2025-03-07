﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
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
        R_AARCH64_IRELATIVE = 1032,
        R_AARCH64_ABS64 = 257
    }

    public class RelocationTable
    {
        public RelocationTable(BinaryReader reader, long numRelocs)
        {
            List<DynamicReloc> relocs = new List<DynamicReloc>();
            for (int i = 0; i < numRelocs; i++)
            {
                DynamicReloc rl = new(reader);
                relocs.Add(rl);
            }
            mRelocs = (Lookup<ulong, DynamicReloc>)relocs.ToLookup(r => r.GetOffset(), r => r);
        }

        public DynamicReloc? GetRelocationAtOffset(ulong offset)
        {
            return mRelocs[offset].FirstOrDefault();
        }

        public Lookup<ulong, DynamicReloc> mRelocs;
    }

    public class DynamicReloc
    {
        public DynamicReloc(BinaryReader reader)
        {
            mOffset = reader.ReadUInt64();
            mInfo = reader.ReadUInt64();
            mAddend = reader.ReadInt64();

            mSymIdx = mInfo >> 32;
            mRelocType = (RelocType)(mInfo & 0xFFFFFFFF);
        }

        public ulong GetOffset()
        {
            return mOffset;
        }

        public ulong GetInfo()
        {
            return mInfo;
        }

        public ulong GetSymIdx()
        {
            return mSymIdx;
        }

        public long GetAddend()
        {
            return mAddend;
        }

        public RelocType GetRelocType()
        {
            return mRelocType;
        }

        ulong mOffset;
        ulong mInfo;
        ulong mSymIdx;
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

        public PLTEntry GetEntryAtAddr(long addr)
        {
            return mEntries.First(e => e.mOffset == addr);
        }

        public PLTEntry GetEntryAtIdx(int idx)
        {
            return mEntries[idx];
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

            mSymIdx = mInfo >> 32;
            mRelocType = (RelocType)(mInfo & 0xFFFFFFFF);
        }

        public long mOffset;
        long mInfo;
        long mAddend;
        public RelocType mRelocType;
        public long mSymIdx;
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

        public List<long> mAddrs = new();
    }
}
