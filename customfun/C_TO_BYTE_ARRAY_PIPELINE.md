# C to Raw Byte Array Pipeline

This guide explains a reproducible workflow for producing raw machine-code bytes from C and converting them into a C/C++ byte array for embedding.

## Goal

Given a source file such as payload.c, produce:

- payload.elf for inspection
- payload.bin with raw bytes
- payload.h (or bytes.inc) containing a byte array

## 1) Write payload-oriented C carefully

For reliable extraction, keep code self-contained:

- Avoid libc calls unless you explicitly link and keep those sections.
- Avoid global initializers that require runtime startup.
- Prefer fixed-width integer types.
- Keep constants close to code so section placement is predictable.

## 2) Compile to object file

Use GCC or Clang:

```bash
gcc -c payload.c -o payload.o \
  -Os \
  -ffreestanding \
  -fno-stack-protector \
  -fno-asynchronous-unwind-tables \
  -fno-unwind-tables \
  -fno-ident \
  -fno-builtin
```

Notes:

- -ffreestanding and -fno-builtin reduce implicit runtime assumptions.
- Unwind-table flags reduce extra metadata sections that are not payload logic.

## 3) Link to an ELF with controlled layout

```bash
ld -o payload.elf payload.o -nostdlib -Ttext=0x0
```

Alternative with GCC as driver:

```bash
gcc payload.o -o payload.elf -nostdlib -Wl,-Ttext=0x0
```

## 4) Inspect before extracting bytes

```bash
readelf -S payload.elf
readelf -r payload.elf
objdump -d payload.elf
```

Check for:

- Unexpected relocations in .text
- Unexpected external symbol dependencies
- Code in sections other than .text that you still need

## 5) Extract raw bytes

Most common case (.text only):

```bash
objcopy -O binary -j .text payload.elf payload.bin
```

If required, include multiple sections explicitly (order matters by linker layout):

```bash
objcopy -O binary \
  -j .text \
  -j .rodata \
  payload.elf payload.bin
```

## 6) Convert .bin to a C array

Using xxd:

```bash
xxd -i payload.bin > payload_bytes.h
```

This creates symbols like:

- payload_bin[]
- payload_bin_len

You can rename symbols with a small post-process step if needed.

## 7) Verify final bytes

```bash
wc -c payload.bin
hexdump -C payload.bin | head
```

If you keep a reference disassembly, compare expected instruction bytes against extracted output.

## Common pitfalls

1. Relocations still present
If relocations exist, raw bytes alone are usually not self-contained.

2. Hidden helper calls
The compiler may emit helper calls depending on operations and target ABI.

3. Position dependence
Code may assume fixed addresses unless written and built for position independence.

4. Section mismatch
Important constants might land in .rodata and be missing if you only extract .text.

5. Toolchain drift
Different compiler versions and flags can change emitted bytes.

## Minimal Makefile snippet

```make
CC := gcc
LD := ld
OBJCOPY := objcopy

CFLAGS := -Os -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident -fno-builtin

all: payload_bytes.h

payload.o: payload.c
	$(CC) -c $< -o $@ $(CFLAGS)

payload.elf: payload.o
	$(LD) -o $@ $< -nostdlib -Ttext=0x0

payload.bin: payload.elf
	$(OBJCOPY) -O binary -j .text $< $@

payload_bytes.h: payload.bin
	xxd -i $< > $@

clean:
	rm -f payload.o payload.elf payload.bin payload_bytes.h
```

## Mapping to this repository

For embedding into [framework/encoders/plugins/embed.cpp](framework/encoders/plugins/embed.cpp), you can:

- Generate payload.bin and payload_bytes.h.
- Transform payload_bytes.h data into the macro form expected by SHELL_PAYLOAD.
- Compile the encoder with that macro so write_shell_payload writes deterministic bytes.
