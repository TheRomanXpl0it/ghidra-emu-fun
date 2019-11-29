# ghidra-emu-fun
Ghidra Emulates Functions

<img align="right" width="200" alt="The love child of Ghidra and an Emu" src="assets/ghidra-fun-emu.png">

This repo hosts a Ghidra script that offers a frontend for Ghidra P-code emulator.

The mission of this project is making the emulation of a function as fun as possible.

## Quick Start

To install this script, clone the repository and add the src directory to the Script Manager.

Open a binary in Ghidra and run emulate_function.py from the script manager.

You should see a new window with a button and a text field. Usually we dock the "console" window right above the emulator plugin window so we can get an experience closer to normal debuggers.


## Roadmap

So here are the next things that we are going to work on:

- Better documentation and tutorials
- Richer library of implemented hooks
- Maybe syscall modelling (but don't count of that)
- Better handling of symbols and types (especially with regards to hooks)
- Implement default behaviour for pcode user ops
  - Add instruction hooks

## Technical Curiosities

### Hooks

So Sleigh allows great flexibility when defining the P-code translation of an instruction, as such there can be code fragments that Ghidra cannot emulate correctly.

We added function hooking to allow the emulation of dynamically linked binaries and bypassing of functions with unsupported P-code instructions.

There is a bit of magic to make writing hooks a fun experience.
Take for example the [puts](https://github.com/TheRomanXpl0it/ghidra-emu-fun/blob/master/src/lib/libc6.py#L22) implementation in lib/libc6.py:

```python
@hooks.args
def puts(p):
    s = []
    i = 0
    while p[i] != '\x00' and i < 1000:
        s.append(p[i])
        i += 1
    logger.info('puts: {}'.format(repr(''.join(s))))
    return 1
```


To make the same implementation of the hook work across different architectures we look at the storage location of the parameters as detected by the decompiler. So as long as the function signature is correct, things "should just work". 
For example, we used the hooks at CSAW ESC on ARM32 binaries and on GameBoy Z80 16-bit architecture for the presentation at DEF CON Group Rome.

If you compare writing a hook like this with other emulation frameworks, you should see that there are some merits in leveraging a mature reverse engineering platform.

The hooks.args function decorator wraps the python implementation of puts and tries to automatically read the parameters from the emulator state.

There are some interesting ideas that we need to complete: at the moment the DataType extracted from Ghidra's analysis (or from manual annotation on Ghidra) are only used to compute the size of the DataType or to distinguish between values and pointers.

Currently values will be converted to byte strings and pointers will be converted into [NativePointers](https://github.com/TheRomanXpl0it/ghidra-emu-fun/blob/master/src/lib/hooks.py#L8) which serve to mediate memory read and writes to the emulator.

Since the signature of puts is `int puts(char *p)` when the emulation hits the hook, the plugin will wrap the relevant portion of memory into a NativePointer (e.g. on Linux x86-64, p will be a NativePointer with base address equal to rdi, but on ARM32 the base address will be r0).

For a dynamically linked binary, the plugin will try automatically to match any import against the functions that have been implemented in lib.

## Contributors

This repository was created from a flattened version of the original repository that we used for CSAW ESC, so the activity shown on GitHub may not reflect the actual contributions made by our team members.

I would like to thank [matteojug](https://github.com/matteojug) for large refactories of the code base, for polishing the ui a bit and for bending jython to register a Ghidra Plugin without using Java.

I also want to thank [pietroborrello](https://github.com/pietroborrello), [CristianRichie](https://github.com/CristianRichie) and [B4dSheeP](https://github.com/B4dSheeP) for testing the emulator.

Finally I would like to thank [andreafioraldi](https://github.com/andreafioraldi) for the precious feedback.
