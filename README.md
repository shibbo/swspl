
# swspl
![Build Status](https://github.com/shibbo/swspl/actions/workflows/main.yml/badge.svg)
[![Discord](https://img.shields.io/discord/1133588984883318884?color=%237289DA&logo=discord&logoColor=%23FFFFFF)](https://discord.gg/QnZ4cKkZm3)

A toolchain used for splitting up Nintendo Switch binaries for decompilation.

# Usage
Currently the splitting ability of swspl is in development.

## Commands
### nso info
Prints information about a given NSO file, similar to objdump.
```shell
$ swspl nso info /path/to/file.nso
```

### nso split
Begins the splitting process for a given NSO file.
```shell
$ swspl nso split /path/to/file.nso /path/to/map.map
```

### nso dump
Dumps the three main sections (`.text`, `.rodata` and `.data`) into binary files.
```shell
$ swspl nso dump /path/to/file.nso
```
