# Static .NET Analyzer

This is a static .NET malware analysis tool that parses embedded metadata such as functions, types and fields. It structures that information and stores it
in objects accessible from plugins via API functions. Plugins can either filter or manipulate structured information, or use it to detect a given malware
strain or obfuscator.

## Installing

dotnet-analyzer requires autoconf and automake on Linux and Mac. On Windows, the Visual Studio solution can be used. Install on Debian/Ubuntu Linux as follows.

```bash
apt-get install automake autoconf make g++
```

Then run the following commands to compile the ananlyzer.

```bash
./autogen.sh
./configure
make
```

## Usage

The help summary can be summoned using the `-h` or `--help` switch.

```
dotnet-analyzer for reversing .NET binaries.
Usage: dotnet-analyzer -f <input_file [options]

Basic parameters:
-h,--help		Requests this help menu.
-v,--verbose		Enables verbose output.
-f,--input-file		Specifies the input binary file.

Output parameters:
-d,--dump-streams	Dumps the contents of detected .NET streams.
-m,--metadata-tokens	Dumps machine-readable list of metadata tokens in the tables.
```



## References

- https://www.cnblogs.com/AndersLiu/archive/2010/02/09/en-compressed-integer-in-metadata.html
- https://www.codeproject.com/Articles/12585/The-NET-File-Format
- https://www.red-gate.com/simple-talk/blogs/anatomy-of-a-net-assembly-clr-metadata-3/
- https://ecma-international.org/publications-and-standards/standards/ecma-335/
