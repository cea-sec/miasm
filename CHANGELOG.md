# Changelog

## [Unreleased]

## 0.1.1 - 2019-01-16
### Added
- Graph: add postdominators computation from [@GAJaloyan](https://github.com/GAJaloyan)
- Multiple X86/MeP/Arm/Amrt/Aarch64 mnemonics ([@guedou](https://github.com/guedou), [@w4kfu](https://github.com/w4kfu), [@nguigo](https://github.com/nguigo))
- Qemu regression tests for X86_64
- Start export of the intermediate language to LLVM
- IR simplifications
- Typos & codespell checker from [@p-l-](https://github.com/p-l-)
- High level flags for MSP430

### Fixed
- Out-of-SSA with new algorithm
- Travis cleanup/rework/improvement from [@stephengroat](https://github.com/stephengroat)
- Jitter: pc update
- Jitter/python: global refactoring
- Change ExprMem pointer access (.ptr instead of .arg)
- Rename IR operators idiv/imod to sdiv/smod for homogeneity
- Clean replace_expr from [@Mizari](https://github.com/Mizari)
- Various fixes
- Instruction to_string from [@nofiv](https://github.com/nofiv)

## 0.1.0 - 2018-11-12
### Added
- Support for Windows added from [@0vercl0k](https://github.com/0vercl0k)
- Support for Appveyor
- Symbolic execution memory management has been rewritten. As a result, the
  global performance of symbolic execution has improved
- Support for some of Thumb2 instructions
- Support for build on OpenBSD
- Support for `mips32b` emulation
- Support for XMMs registers / 128 bits operations for all jitter engine
- New IR word: ExpLoc (representing a location in the code)
- New symbol management: LocationDB (replacing symbol_pool)
- Split IRCFG from IntermediateRepresntation
- SSA transformation added from [@mrphrazer](https://github.com/mrphrazer)
- Support ELF relocations
- Support for SSE (with qemu test)
- Support for full Linux environment emulation + syscall
- Support for explicit flags (eflags + size extend)
- Support for (buggy) un-ssa
- Improvement of floats handling
- Added Toshiba MeP architecture added from [@guedou](https://github.com/guedou)
- Add constant expressions propagation (ssa based)
- Support for ARM SVC added from [@aguinet](https://github.com/aguinet)
- Introduce `ExprMem.ptr`
- Add various expression simplifications
- Add immediate postdominator computation from [@GAJaloyan](https://github.com/GAJaloyan)

### Removed
- TCC support is dropped
### Fixed
- Trace api improved
- Various fixes for the PPC architecture
- Various fixes for the x86 architecture
- Various fixes for ARM instructions
- Various fixes in IDA plugins
- Various code refactoring
- No more default size in any `Expr`
- `ExprAff` renamed to `ExprAssign`
- Problems who might occurs when comparing for inequality (`!=`) in some of
  Miasm objects
- Instruction parsing codes have been cleaned and simplified
- Resource rebuilding for PE
- Better BigEndian handling in Miasm
- Misleading name `EXCEPT_BREAKPOINT_INTERN` is renamed `EXCEPT_BREAKPOINT_MEMORY`
- Gentoo compilation
- Jitter memory page management
- Sanitization of floats representation
- Fix build on 32 bit machines
- Fix DSE read/write bug
- Sandbox's option `use-seh` renamed to the more precise `use-windows-structs`
- Clean simplifier cache on pass enabling

## 0.0.1 - 2018-03-12
### Added
- This CHANGELOG file
- Version tracking

[Unreleased]: https://github.com/cea-sec/miasm/compare/v0.1.0...HEAD
