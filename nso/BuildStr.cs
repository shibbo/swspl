using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace swspl.nso
{
    public class BuildStr
    {
        public BuildStr(BinaryReader reader)
        {
            // skip
            reader.ReadBytes(4);
            int strLen = reader.ReadInt32();
            mBuildStr = Util.ReadString(reader, strLen);
        }

        public int Len()
        {
            return mBuildStr.Length;
        }

        string mBuildStr;
    }
}
