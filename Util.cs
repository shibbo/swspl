﻿using System;
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
    }
}
