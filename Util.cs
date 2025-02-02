using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace swspl
{
    public static class Util
    {
        public static string ReadString(BinaryReader reader, int length)
        {
            byte[] buf = new byte[length];

            for (int i = 0; i < length; i++)
            {
                buf[i] = reader.ReadByte();
            }

            return Encoding.ASCII.GetString(buf);
        }

        public static string ReadStringNT(BinaryReader reader)
        {
            List<byte> str = new();

            while (true)
            {
                byte b = reader.ReadByte();
                
                if (b == 0)
                {
                    break;
                }

                str.Add(b);
            }

            return Encoding.ASCII.GetString(str.ToArray());
        }

        public static byte[] GetSHA(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        public static bool ArrayEqual(byte[] _1, byte[] _2)
        {
            if (_1.Length != _2.Length)
            {
                return false;
            }

            for (int i = 0; i < _1.Length; i++)
            {
                if (_1[i] != _2[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static bool IsBranchInstr(string instr)
        {
            switch (instr)
            {
                case "b":
                case "b.ne":
                case "b.mi":
                case "b.cc":
                case "b.ge":
                case "b.lt":
                case "b.le":
                case "b.gt":
                case "b.lo":
                case "b.ls":
                case "b.hi":
                case "b.hs":
                case "b.eq":
                case "b.pl":
                case "b.vc":
                case "b.vs":
                case "tbz":
                case "tbnz":
                case "cbz":
                case "cbnz":
                    return true;
                default:
                    return false;
            }
        }

        public static bool IsLocalBranchInstr(string instr)
        {
            switch (instr)
            {
                case "b.ne":
                case "b.cc":
                case "b.ge":
                case "b.lt":
                case "b.le":
                case "b.ls":
                case "b.gt":
                case "b.lo":
                case "b.mi":
                case "b.hs":
                case "b.hi":
                case "b.eq":
                case "b.pl":
                case "b.vc":
                case "b.vs":
                    return true;
                default:
                    return false;
            }
        }

        public static ulong FindClosestKey(long target, IEnumerable<ulong> keys)
        {
            return keys.Aggregate((minKey, nextKey) =>
                Math.Abs((long)nextKey - target) < Math.Abs((long)minKey - target) ? nextKey : minKey);
        }

        public static ulong? FindClosestKeyAbove(long target, IEnumerable<ulong> keys)
        {
            var filteredKeys = keys.Where(k => (long)k >= target);
            return filteredKeys.Any()
                ? filteredKeys.Aggregate((minKey, nextKey) =>
                    Math.Abs((long)nextKey - target) < Math.Abs((long)minKey - target) ? nextKey : minKey)
                : (ulong?)null;
        }

        public static ulong? FindClosestKeyAboveNEq(long target, IEnumerable<ulong> keys)
        {
            var filteredKeys = keys.Where(k => (long)k > target);
            return filteredKeys.Any()
                ? filteredKeys.Aggregate((minKey, nextKey) =>
                    Math.Abs((long)nextKey - target) < Math.Abs((long)minKey - target) ? nextKey : minKey)
                : (ulong?)null;
        }

        public static bool IsValidUtf8(byte[] bytes)
        {
            int i = 0;
            while (i < bytes.Length)
            {
                byte b = bytes[i];

                // b != 0 helps prevent false positives
                if (b <= 0x7F && b != 0)
                {
                    i++;
                }
                else if ((b >= 0xC0 && b <= 0xDF) && (i + 1 < bytes.Length && (bytes[i + 1] & 0xC0) == 0x80))
                {
                    i += 2;
                }
                else if ((b >= 0xE0 && b <= 0xEF) && (i + 2 < bytes.Length && (bytes[i + 1] & 0xC0) == 0x80 && (bytes[i + 2] & 0xC0) == 0x80))
                {
                    i += 3;
                }
                else if ((b >= 0xF0 && b <= 0xF7) && (i + 3 < bytes.Length && (bytes[i + 1] & 0xC0) == 0x80 && (bytes[i + 2] & 0xC0) == 0x80 && (bytes[i + 3] & 0xC0) == 0x80))
                {
                    i += 4;
                }
                else
                {
                    return false;
                }
            }
            return true;
        }

        public static byte[] TrimNullTerminator(byte[] bytes)
        {
            if (bytes.Length > 0 && bytes[^1] == 0x00)
            {
                Array.Resize(ref bytes, bytes.Length - 1);
            }
            return bytes;
        }
    }
}
