# Changelog

## 1.0.0 — work-in-progress checkpoint

Partial code published for continued development. Known issues: STATUS.md.

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-10-25

### Added
- Core infrastructure: FastAPI + React skeleton for reverse engineering workbench
- Backend API with binary upload (`POST /api/upload`)
- Disassembly endpoint using Capstone (`GET /api/disasm/{file_id}`)
  - Supports x86 (16/32/64-bit), ARM (32/64-bit), MIPS (32/64-bit LE/BE)
- Binary metadata endpoint (`GET /api/info/{file_id}`)
- Health check endpoint (`GET /health`)
- Frontend with file upload UI and disassembly table display
- Architecture/mode/offset/count controls for disassembly
- CORS configuration for frontend-backend integration
- Comprehensive test suite
  - Backend: 7 tests (health, upload, disassembly x86/ARM, binary info, 404)
  - Frontend: 4 tests (rendering, file selection, upload button state)

### Technical Details
- Backend: FastAPI, Uvicorn, Capstone 5.0.5, Pydantic 2
- Frontend: React 18, TypeScript, Vite, TanStack Query, Axios
- Testing: pytest (backend), Vitest + React Testing Library (frontend)

### Known Limitations
- In-memory binary storage (ephemeral)
- No authentication/authorization
- Disassembly view not virtualized for large outputs
- Basic error handling only
