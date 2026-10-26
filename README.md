# Orbit Workbench

> Work in progress. This checkpoint may be incomplete or fail tests. See PLAN.md and STATUS.md before use.


A reverse engineering workbench for binary analysis, inspired by Ghidra.

## Quick Start

### Backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
# Server runs on http://localhost:8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:5173 (proxies /api to backend)
```

## API Endpoints

- `GET /health` - Health check
- `POST /api/upload` - Upload binary file
- `GET /api/disasm/{file_id}` - Disassemble binary
- `GET /api/info/{file_id}` - Get binary metadata

## Testing

```bash
# Backend tests
cd backend && source venv/bin/activate && python -m pytest test_main.py -v

# Frontend tests
cd frontend && npm test -- --run
```

## Roadmap

See [PLAN.md](PLAN.md) for detailed roadmap.

### Current Focus
- Vtable function call resolution (Issue #516)
- Switch statement recognition (Issue #2628)
- JMP+PUSH call recognition (Issue #5747)
- M68000 lineA/lineF support (Issue #487)
- String display across segments (Issue #4865)
- Batch decompilation optimization (Issue #2791)

## License
Apache-2.0

Maintainer: Alan Vo <alanvo@gmail.com>
