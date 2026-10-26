"""
Orbit Workbench - FastAPI Backend
Binary analysis and reverse engineering API.
"""
import os
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_MIPS64, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN

app = FastAPI(title="Orbit Workbench API", version="0.1.0")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Storage for uploaded binaries (in-memory for MVP)
UPLOAD_DIR = Path("/tmp/orbit-workbench/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

binary_store: dict[str, dict] = {}


class HealthResponse(BaseModel):
    status: str
    version: str


class UploadResponse(BaseModel):
    file_id: str
    filename: str
    size: int
    message: str


class DisasmRequest(BaseModel):
    file_id: str
    arch: str = "x86"
    mode: str = "32"
    base_address: int = 0x1000
    offset: int = 0
    count: int = 100


class Instruction(BaseModel):
    address: int
    mnemonic: str
    op_str: str
    bytes: str


class DisasmResponse(BaseModel):
    file_id: str
    instructions: list[Instruction]
    total_count: int
    arch: str
    mode: str


def get_capstone_arch(arch: str, mode: str):
    """Map arch/mode strings to capstone constants."""
    arch = arch.lower()
    mode = mode.lower()
    
    if arch == "x86":
        if mode in ("16", "32"):
            return Cs(CS_ARCH_X86, CS_MODE_32)
        elif mode == "64":
            return Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == "arm":
        if mode == "32":
            return Cs(CS_ARCH_ARM, CS_MODE_ARM)
        elif mode == "64":
            return Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif arch == "mips":
        if mode == "32":
            return Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
        elif mode == "64":
            return Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)
    elif arch == "mipsbe":
        if mode == "32":
            return Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN)
        elif mode == "64":
            return Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN)
    
    # Default to x86 32-bit
    return Cs(CS_ARCH_X86, CS_MODE_32)


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(status="ok", version="0.1.0")


@app.post("/api/upload", response_model=UploadResponse)
async def upload_binary(file: UploadFile = File(...)):
    """Upload a binary file for analysis."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    content = await file.read()
    file_id = str(uuid.uuid4())
    file_path = UPLOAD_DIR / file_id
    
    # Save file
    with open(file_path, "wb") as f:
        f.write(content)
    
    # Store metadata
    binary_store[file_id] = {
        "filename": file.filename,
        "path": str(file_path),
        "size": len(content),
    }
    
    return UploadResponse(
        file_id=file_id,
        filename=file.filename,
        size=len(content),
        message="Binary uploaded successfully"
    )


@app.get("/api/disasm/{file_id}", response_model=DisasmResponse)
async def disassemble(
    file_id: str,
    arch: str = Query("x86", description="Architecture: x86, arm, mips, mipsbe"),
    mode: str = Query("32", description="Mode: 16, 32, 64"),
    base_address: int = Query(0x1000, description="Base address for disassembly"),
    offset: int = Query(0, description="Offset into binary"),
    count: int = Query(100, description="Number of instructions to disassemble"),
):
    """Disassemble binary using capstone."""
    if file_id not in binary_store:
        raise HTTPException(status_code=404, detail="Binary not found")
    
    binary_info = binary_store[file_id]
    file_path = binary_info["path"]
    
    with open(file_path, "rb") as f:
        f.seek(offset)
        code = f.read(count * 16)  # Read enough bytes for count instructions
    
    if not code:
        return DisasmResponse(
            file_id=file_id,
            instructions=[],
            total_count=0,
            arch=arch,
            mode=mode
        )
    
    md = get_capstone_arch(arch, mode)
    md.detail = True
    
    instructions = []
    for insn in md.disasm(code, base_address + offset):
        if len(instructions) >= count:
            break
        instructions.append(Instruction(
            address=insn.address,
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            bytes=insn.bytes.hex()
        ))
    
    return DisasmResponse(
        file_id=file_id,
        instructions=instructions,
        total_count=len(instructions),
        arch=arch,
        mode=mode
    )


@app.get("/api/info/{file_id}")
async def binary_info(file_id: str):
    """Get binary metadata."""
    if file_id not in binary_store:
        raise HTTPException(status_code=404, detail="Binary not found")
    return binary_store[file_id]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
