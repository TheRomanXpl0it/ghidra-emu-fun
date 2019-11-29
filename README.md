# ghidra-emu-fun
Ghidra Emulates Functions

<img align="right" width="200" alt="The love child of Ghidra and an Emu" src="assets/ghidra-fun-emu.png">

This repo hosts a Ghidra script that offers a frontend for Ghidra P-code emulator.

The mission of this project is making the emulation of a function as fun as possible.

## Roadmap

So here are the next things that we are going to work on:

- Better documentation and tutorials
- Richer library of implemented hooks
- Maybe syscall modelling (but don't count of that)
- Better handling of symbols and types (especially with regards to hooks)
- Implement default behaviour for pcode user ops
  - Add instruction hooks
## Contributors

This repository was created from a flattened version of the original repository that we used for CSAW ESC, so the activity shown on GitHub may not reflect the actual contributions made by our team members.

I would like to thank [matteojug](https://github.com/matteojug) for large refactories of the code base, for polishing the ui a bit and for bending jython to register a Ghidra Plugin without using Java.

I also want to thank [pietroborrello](https://github.com/pietroborrello), [CristianRichie](https://github.com/CristianRichie) and [B4dSheeP](https://github.com/B4dSheeP) for testing the emulator.

Finally I would like to thank [andreafioraldi](https://github.com/andreafioraldi) for the precious feedback.
