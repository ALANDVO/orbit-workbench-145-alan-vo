# Product development plan

Each round completes one feature or repair. Future items are planned, not implemented claims.

## Current round

core-infrastructure

## Roadmap

### core-infrastructure — Core Infrastructure: FastAPI + React skeleton with binary upload and basic analysis

Status: done

Acceptance:
- FastAPI server starts and serves health endpoint
- React frontend loads and connects to backend
- Binary file upload endpoint works
- Basic disassembly listing returned for uploaded binary

Implementation: `backend/main.py`, `backend/requirements.txt`, `frontend/package.json`, `frontend/src/App.tsx`, `frontend/src/main.tsx`

Tests: `backend/test_main.py`, `frontend/src/App.test.tsx`

### vtable-resolution — Vtable Function Call Resolution in Decompiler

Status: planned

Acceptance:
- Decompiler shows resolved vtable function names instead of raw indices
- User can annotate vtable structures
- Cross-references to vtable entries work

### switch-decompilation — Switch Statement Recognition

Status: planned

Acceptance:
- Jump table patterns recognized as switch statements
- Case values and targets displayed in decompiler output

### jmp-push-call-recognition — JMP with PUSH Return Address Recognition

Status: planned

Acceptance:
- PUSH + JMP sequences recognized as CALL with return
- Decompiler shows proper control flow without spurious returns

### m68k-linea-linef — M68000 lineA/lineF Opcode Support

Status: planned

Acceptance:
- lineA (0xAxxx) and lineF (0xFxxx) opcodes decode
- Vector table references at 0x0A/0x0B resolved

### string-display-decompiler — String Display in Decompiler Across Segments

Status: planned

Acceptance:
- String references resolved across memory segments
- Decompiler shows string literals instead of raw addresses

### batch-decompilation-performance — Batch Decompilation Performance Optimization

Status: planned

Acceptance:
- Concurrent decompilation scales beyond 10 threads
- I/O bottleneck identified and mitigated

