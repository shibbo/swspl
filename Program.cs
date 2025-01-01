﻿using swspl.nso;
using System;
using System.Diagnostics;

class Progam
{
    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            ShowHelp();
            return;
        }

        switch (args[0].ToLower())
        {
            case "-help":
                if (args.Length == 2)
                {
                    ShowHelp(args[1]);
                }
                else
                {
                    ShowHelp();
                }
                break;

            case "dump":
                {
                    string filename = args[1];
                    NSO nso = new NSO(filename, true);
                    nso.ExportSectionBinaries();
                    break;
                }

            case "info":
                {
                    string filename = args[1];
                    NSO nso = new NSO(filename, true);
                    nso.PrintInfo();
                    break;
                }

            case "split":
                if (args.Length == 2)
                {
                    string filename = args[1];
                    Stopwatch sw = new();
                    sw.Start();
                    NSO nso = new NSO(filename, false);
                    sw.Stop();
                    TimeSpan span = sw.Elapsed;
                    Console.WriteLine($"NSO::NSO Time -- {span.TotalSeconds} seconds");
                    nso.SaveToFile();
                }
                else
                {
                    Console.WriteLine("Error: The 'split' option requires a filename.");
                }
                break;

            default:
                Console.WriteLine("Unknown command. Use '-help' for available options.");
                break;
        }
    }

    static void ShowHelp()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  swspl.exe -help [option]");
        Console.WriteLine("Options:");
        Console.WriteLine("  split   Splits the given file into assembly.");
        Console.WriteLine("  dump   Exports binaries (decompressed) of each section of an NSO.");
        Console.WriteLine("  info   Exports information about the given file.");
        Console.WriteLine();
        Console.WriteLine("Use 'swspl.exe -help option' to get more details about a specific option.");
    }

    static void ShowHelp(string opt)
    {
        switch (opt.ToLower())
        {
            case "dump":
                Console.WriteLine("Exports binaries (decompressed) of each section of an NSO.");
                break;
            case "split":
                Console.WriteLine("Splits the given file into multiple parts and exports their assembly.");
                break;
            case "info":
                Console.WriteLine("Prints out information about the given file (ie relocation data, symbol dump, etc");
                break;
            default:
                break;
        }
    }
}