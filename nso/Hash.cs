using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace swspl.nso
{
    public class HashTable
    {
        public HashTable(BinaryReader reader)
        {
            uint numBuckets = reader.ReadUInt32();
            uint numChain = reader.ReadUInt32();

            for (int i = 0; i < numBuckets; i++)
            {
                buckets.Add(reader.ReadUInt32());
            }

            for (int i = 0; i < numChain; i++)
            {
                chains.Add(reader.ReadUInt32());
            }

            uint butts = chains.Last();
        }

        List<uint> buckets = new();
        List<uint> chains = new();
    }

    public class GNUHashTable
    {
        public GNUHashTable(BinaryReader reader)
        {
            uint numBuckets = reader.ReadUInt32();
            uint symIdx = reader.ReadUInt32();
            uint mask = reader.ReadUInt32();
            uint shift = reader.ReadUInt32();

            for (int i = 0; i < mask; i++)
            {
                bloomFilter.Add(reader.ReadUInt64());
            }

            for (int i = 0; i < numBuckets; i++)
            {
                buckets.Add(reader.ReadUInt32());
            }

            // we do not know the number of chains
            while (true)
            {
                uint val = reader.ReadUInt32();

                if (val == 0)
                {
                    break;
                }

                chains.Add(val);
            }
        }

        List<ulong> bloomFilter = new();
        List<uint> buckets = new();
        List<uint> chains = new();
    }
}
