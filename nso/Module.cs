using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace swspl.nso
{
    public class Module
    {
        public Module(BinaryReader reader)
        {
            // TODO -- version checking
            reader.ReadBytes(0x4);
            uint headerOffset = reader.ReadUInt32();

            if (Util.ReadString(reader, 4) != "MOD0")
            {
                throw new Exception("Module::Module(BinaryReader) -- Invalid MOD0 magic.");
            }

            // all of these offsets are relative to the beginning of the module
            // so we add the header offset to each offset
            mDynOffset = reader.ReadUInt32() + headerOffset;
            mBssStart = reader.ReadUInt32() + headerOffset;
            mBssEnd = reader.ReadUInt32() + headerOffset;
            mExInfoStartOffs = reader.ReadUInt32() + headerOffset;
            mExInfoEndOffs = reader.ReadUInt32() + headerOffset;
            mModuleOffs = reader.ReadUInt32() + headerOffset;

            if (mBssStart != mModuleOffs)
            {
                Console.WriteLine("BSS Start != Module offset. Investigate this.");
            }
        }

        public uint mDynOffset;
        public uint mBssStart;
        public uint mBssEnd;
        public uint mExInfoStartOffs;
        public uint mExInfoEndOffs;
        public uint mModuleOffs;
    }
}
