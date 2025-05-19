using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace swspl.nso
{
    public static class Map
    {
        public static void LoadMap(string path)
        {
            string[] lines = File.ReadAllLines(path);
            bool parsingData = false;

            foreach (string line in lines)
            {
                if (line == "START_DATA")
                {
                    parsingData = true;
                    continue;
                }

                if (parsingData == false)
                {
                    string[] spl = line.Split("\t");
                    string sym = spl[0];

                    if (sym == "Function name" || GetSymbolByName(sym) != null)
                    {
                        continue;
                    }

                    if (sym.StartsWith("sub_"))
                    {
                        sym = sym.Replace("sub_", "fn_");
                    }

                    string seg = spl[1];
                    ulong addr = Convert.ToUInt64(spl[2], 16);

                    if (sym.StartsWith("nullsub_"))
                    {
                        sym = $"fn_{addr:X}";
                    }

                    int size = Convert.ToInt32(spl[3], 16);
                    mSymbols.Add(addr, new Symbol(sym, seg, addr, size));
                    mSymbolToAddr.Add(sym, addr);

                    if (seg == ".text")
                    {
                        if (addr < StartAddress)
                        {
                            StartAddress = addr;
                        }

                        ulong end = addr + (ulong)size;
                        if (end > EndAddress)
                        {
                            EndAddress = end;
                        }
                    }
                }
                else
                {
                    string[] spl = line.Split(" ");
                    string sym = spl[8];
                    if (sym.StartsWith("jpt"))
                    {
                        continue;
                    }

                    ulong addr = Convert.ToUInt64(spl[1].Split(":")[1], 16);
                    mSymbols.Add(addr, new Symbol(sym, ".rodata", addr, -1));
                    mSymbolToAddr.Add(sym, addr);
                }
            }
        }

        public static Symbol? GetSymbolByName(string name)
        {
            if (!mSymbolToAddr.TryGetValue(name, out ulong addr))
                return null;
            return mSymbols[addr];
        }

        public static bool IsInText(ulong addr)
        {
            return (StartAddress <= addr) && (addr <= EndAddress);
        }

        public static int GetSymbolSize(string sym)
        {
            Symbol? symbol = GetSymbolByName(sym);
            if (symbol == null)
                return 0;
            return symbol.GetSize();
        }

        public static string GetSymbolAtAddr(ulong addr)
        {
            if (!mSymbols.TryGetValue(addr, out Symbol? symbol) || symbol == null)
                return "UNK";
            return symbol.GetName();
        }

        public static ulong GetSymbolAddr(string sym)
        {
            Symbol? symbol = GetSymbolByName(sym);
            if (symbol == null)
                return 0;
            return symbol.GetAddr();
        }

        private static Dictionary<string, ulong> mSymbolToAddr = new();
        public static Dictionary<ulong, Symbol> mSymbols = new();
        private static ulong StartAddress;
        private static ulong EndAddress;

        public class Symbol
        {
            public Symbol(string name, string seg, ulong addr, int size)
            {
                mName = name;
                mSegment = seg;
                mAddr  = addr;
                mSize = size;
            }

            public int GetSize()
            {
                return mSize;
            }

            public ulong GetAddr()
            {
                return mAddr;
            }

            public string GetName()
            {
                return mName;
            }

            string mName;
            string mSegment;
            ulong mAddr;
            int mSize;
        }
    }
}
