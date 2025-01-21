using swspl.nso;

class Program
{
    static void Main(string[] args)
    {
        System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);

        if (args.Length == 0)
        {
            ShowHelp();
            return;
        }

        string primaryCommand = args[0].ToLower();

        switch (primaryCommand)
        {
            case "help":
                if (args.Length == 2)
                {
                    ShowHelp(args[1]);
                }
                else
                {
                    ShowHelp();
                }
                break;

            case "nso":
            case "nro":
                if (args.Length < 2)
                {
                    Console.WriteLine($"Error: The '{primaryCommand}' command requires a subcommand.");
                    return;
                }

                string subCommand = args[1].ToLower();
                HandleSubCommand(primaryCommand, subCommand, args);
                break;

            default:
                Console.WriteLine("Unknown command. Use '-help' for available options.");
                break;
        }
    }

    static void HandleSubCommand(string primaryCommand, string subCommand, string[] args)
    {
        switch (subCommand)
        {
            case "info":
                if (args.Length < 3)
                {
                    Console.WriteLine($"Error: The '{primaryCommand} info' command requires a filename.");
                    return;
                }

                string filename = args[2];
                if (primaryCommand == "nso")
                {
                    NSO nso = new NSO(filename, true);
                    nso.PrintInfo();
                }
                else if (primaryCommand == "nro")
                {

                }
                break;

            case "split":
                if (args.Length < 3)
                {
                    Console.WriteLine($"Error: The '{primaryCommand} info' command requires a filename.");
                    return;
                }

                filename = args[2];
                if (primaryCommand == "nso")
                {
                    NSO nso = new NSO(filename, false);
                    nso.SaveToFile();
                }
                else if (primaryCommand == "nro")
                {

                }
                break;

            default:
                Console.WriteLine($"Unknown subcommand '{subCommand}' for '{primaryCommand}'.");
                break;
        }
    }

    static void ShowHelp()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  swspl.exe help [option]");
        Console.WriteLine("  swspl.exe nso [subcommand] [filename]");
        Console.WriteLine("  swspl.exe nro [subcommand] [filename]");
        Console.WriteLine("Options:");
        Console.WriteLine("  nso   NSO (Nintendo Switch Object)");
        Console.WriteLine("  nro   NRO (Nintendo Reloctable Object)");
        Console.WriteLine();
        Console.WriteLine("Subcommands:");
        Console.WriteLine("  split   Splits the given file into assembly.");
        Console.WriteLine("  dump   Exports binaries (decompressed) of each section of a given file.");
        Console.WriteLine("  info   Exports information about the given file.");
        Console.WriteLine();
        Console.WriteLine("Use 'swspl.exe help option' to get more details about a specific option.");
    }

    static void ShowHelp(string opt)
    {
        switch (opt.ToLower())
        {
            case "dump":
                Console.WriteLine("Exports binaries (decompressed) of each section of an given file.");
                break;
            case "split":
                Console.WriteLine("Splits the given file into multiple parts and exports their assembly.");
                break;
            case "info":
                Console.WriteLine("Prints out information about the given file (ie relocation data, symbol dump, etc)");
                break;
            default:
                Console.WriteLine($"No help available for '{opt}'.");
                break;
        }
    }
}
