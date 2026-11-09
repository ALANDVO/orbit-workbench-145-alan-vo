"""
Orbit Workbench - FastAPI Backend
Binary analysis and reverse engineering API.
"""
import os
import uuid
import re
from pathlib import Path
from typing import Optional, List, Dict, Any

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


class VtableEntry(BaseModel):
    address: int
    function_name: str
    index: int


class Vtable(BaseModel):
    address: int
    size: int
    entries: list[VtableEntry]
    class_name: str | None = None


class VtableAnalysisResponse(BaseModel):
    file_id: str
    vtables: list[Vtable]
    resolved_calls: list[dict]


class SwitchCase(BaseModel):
    value: int
    target_address: int


class SwitchStatement(BaseModel):
    address: int
    jump_table_address: int
    jump_table_size: int
    cases: list[SwitchCase]
    default_target: int | None = None
    comparison_register: str | None = None
    index_register: str | None = None


class SwitchAnalysisResponse(BaseModel):
    file_id: str
    switches: list[SwitchStatement]


def analyze_vtables(file_id: str, arch: str, mode: str, base_address: int = 0x1000):
    """Analyze binary for vtable structures and resolve indirect calls."""
    if file_id not in binary_store:
        raise HTTPException(status_code=404, detail="Binary not found")
    
    binary_data = binary_store[file_id]["data"]
    md = get_capstone_arch(arch, mode)
    md.detail = True
    
    instructions = list(md.disasm(binary_data, base_address))
    
    # Simple vtable detection: look for arrays of function pointers
    # In x86, this often appears as a series of addresses in .data/.rodata
    vtables = []
    resolved_calls = []
    
    # Scan for potential vtable patterns: consecutive addresses pointing to code
    for i in range(len(binary_data) - 8):
        if arch == "x86" and mode == "64":
            # 64-bit pointers
            ptr1 = int.from_bytes(binary_data[i:i+8], 'little')
            ptr2 = int.from_bytes(binary_data[i+8:i+16], 'little') if i+16 <= len(binary_data) else 0
            # Check if they point to executable regions (rough heuristic)
            if base_address <= ptr1 < base_address + len(binary_data) and base_address <= ptr2 < base_address + len(binary_data):
                # Potential vtable found
                entries = []
                for j in range(10):  # Check up to 10 entries
                    offset = i + j * 8
                    if offset + 8 <= len(binary_data):
                        ptr = int.from_bytes(binary_data[offset:offset+8], 'little')
                        if base_address <= ptr < base_address + len(binary_data):
                            entries.append(VtableEntry(
                                address=ptr,
                                function_name=f"sub_{ptr:x}",
                                index=j
                            ))
                        else:
                            break
                    else:
                        break
                if len(entries) >= 2:
                    vtables.append(Vtable(
                        address=base_address + i,
                        size=len(entries) * 8,
                        entries=entries,
                        class_name=None
                    ))
    
    # Find indirect calls that might use vtables
    for insn in instructions:
        if insn.mnemonic == "call" and insn.op_str and ("[" in insn.op_str or "ptr" in insn.op_str.lower()):
            # Try to match with vtable entries
            for vtable in vtables:
                for entry in vtable.entries:
                    if f"{entry.address:x}" in insn.op_str.lower() or f"{entry.address}" in insn.op_str:
                        resolved_calls.append({
                            "call_address": insn.address,
                            "vtable_address": vtable.address,
                            "entry_index": entry.index,
                            "function_name": entry.function_name
                        })
    
    return VtableAnalysisResponse(
        file_id=file_id,
        vtables=vtables,
        resolved_calls=resolved_calls
    )


def analyze_switches(file_id: str, arch: str, mode: str, base_address: int = 0x1000):
    """Analyze binary for switch statement patterns (jump tables)."""
    if file_id not in binary_store:
        raise HTTPException(status_code=404, detail="Binary not found")
    
    binary_data = binary_store[file_id]["data"]
    md = get_capstone_arch(arch, mode)
    md.detail = True
    
    instructions = list(md.disasm(binary_data, base_address))
    
    switches = []
    
    # Pattern detection for x86/x64 switch statements
    # Common pattern: cmp reg, max_case; ja default; jmp [table + reg*4/8]
    if arch == "x86":
        ptr_size = 4 if mode == "32" else 8
        
        for i, insn in enumerate(instructions):
            # Look for comparison followed by conditional jump and indirect jump
            if insn.mnemonic in ("cmp", "test") and i + 2 < len(instructions):
                next_insn = instructions[i + 1]
                jump_insn = instructions[i + 2]
                
                # Check for: cmp reg, imm; ja/jb/jg/jl default; jmp [base + reg*scale]
                if next_insn.mnemonic in ("ja", "jb", "jae", "jbe", "jg", "jl", "jge", "jle", "jmp") and \
                   jump_insn.mnemonic in ("jmp", "call") and "[" in jump_insn.op_str:
                    
                    # Extract comparison register and max value
                    cmp_op = insn.op_str
                    comparison_register = None
                    max_case = None
                    
                    # Parse cmp reg, imm
                    parts = cmp_op.split(",")
                    if len(parts) == 2:
                        comparison_register = parts[0].strip()
                        try:
                            max_case = int(parts[1].strip(), 16) if parts[1].strip().startswith("0x") else int(parts[1].strip())
                        except ValueError:
                            pass
                    
                    # Parse jump table address from indirect jump
                    # Pattern: jmp [rax*4 + 0x1234] or jmp [table + reg*8]
                    jump_table_addr = None
                    index_register = None
                    
                    # Simple regex for jump table pattern
                    jmp_match = re.search(r'\[([^\]]+)\]', jump_insn.op_str)
                    if jmp_match:
                        addr_expr = jmp_match.group(1)
                        # Look for base address in the expression
                        # Common forms: reg*scale + disp, disp + reg*scale, [reg + disp]
                        hex_matches = re.findall(r'0x[0-9a-fA-F]+|\d+', addr_expr)
                        if hex_matches:
                            try:
                                jump_table_addr = int(hex_matches[0], 16) if hex_matches[0].startswith("0x") else int(hex_matches[0])
                                # Add base_address if it's a relative offset
                                if jump_table_addr < base_address:
                                    jump_table_addr += base_address
                            except ValueError:
                                pass
                        
                        # Extract index register
                        reg_match = re.search(r'\b([re]?[abcdsi][px]?|r\d+)\b', addr_expr)
                        if reg_match:
                            index_register = reg_match.group(1)
                    
                    if jump_table_addr is not None and max_case is not None:
                        # Read jump table entries
                        cases = []
                        table_offset = jump_table_addr - base_address
                        if 0 <= table_offset < len(binary_data):
                            for case_idx in range(max_case + 1):
                                entry_offset = table_offset + case_idx * ptr_size
                                if entry_offset + ptr_size <= len(binary_data):
                                    target = int.from_bytes(
                                        binary_data[entry_offset:entry_offset + ptr_size], 
                                        'little'
                                    )
                                    if base_address <= target < base_address + len(binary_data):
                                        cases.append(SwitchCase(
                                            value=case_idx,
                                            target_address=target
                                        ))
                        
                        if cases:
                            switches.append(SwitchStatement(
                                address=insn.address,
                                jump_table_address=jump_table_addr,
                                jump_table_size=len(cases) * ptr_size,
                                cases=cases,
                                comparison_register=comparison_register,
                                index_register=index_register
                            ))
    
    return SwitchAnalysisResponse(
        file_id=file_id,
        switches=switches
    )


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(status="ok", version="0.1.0")


@app.post("/api/upload", response_model=UploadResponse)
async def upload_binary(file: UploadFile = File(...)):
    """Upload a binary file for analysis."""
    file_id = str(uuid.uuid4())
    content = await file.read()
    
    file_path = UPLOAD_DIR / file_id
    file_path.write_bytes(content)
    
    binary_store[file_id] = {
        "filename": file.filename,
        "size": len(content),
        "data": content,
        "path": str(file_path)
    }
    
    return UploadResponse(
        file_id=file_id,
        filename=file.filename or "unknown",
        size=len(content),
        message="Binary uploaded successfully"
    )


@app.get("/api/disasm/{file_id}", response_model=DisasmResponse)
async def disassemble(
    file_id: str,
    arch: str = Query("x86", description="Architecture: x86, arm, arm64, mips"),
    mode: str = Query("32", description="Mode: 16, 32, 64, arm, thumb"),
    base_address: int = Query(0x1000, description="Base address for disassembly"),
    offset: int = Query(0, description="Offset into binary"),
    count: int = Query(100, description="Maximum number of instructions")
):
    """Disassemble binary using capstone."""
    if file_id not in binary_store:
        raise HTTPException(status_code=404, detail="Binary not found")
    
    binary_data = binary_store[file_id]["data"]
    md = get_capstone_arch(arch, mode)
    md.detail = True
    
    instructions = []
    for insn in md.disasm(binary_data[offset:], base_address + offset):
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


@app.get("/api/vtable/{file_id}", response_model=VtableAnalysisResponse)
async def analyze_vtable(
    file_id: str,
    arch: str = Query("x86", description="Architecture: x86, arm, arm64, mips"),
    mode: str = Query("64", description="Mode: 32, 64"),
    base_address: int = Query(0x1000, description="Base address for analysis")
):
    """Analyze binary for vtable structures and resolve indirect calls."""
    return analyze_vtables(file_id, arch, mode, base_address)


@app.get("/api/switch/{file_id}", response_model=SwitchAnalysisResponse)
async def analyze_switch(
    file_id: str,
    arch: str = Query("x86", description="Architecture: x86, arm, arm64, mips"),
    mode: str = Query("32", description="Mode: 32, 64"),
    base_address: int = Query(0x1000, description="Base address for analysis")
):
    """Analyze binary for switch statement patterns (jump tables)."""
    return analyze_switches(file_id, arch, mode, base_address)


@app.get("/api/info/{file_id}")
async def binary_info(file_id: str):
    """Get binary metadata."""
    if file_id not in binary_store:
        raise HTTPException(status_code=404, detail="Binary not found")
    return {"file_id": file_id, "filename": binary_store[file_id]["filename"], "size": binary_store[file_id]["size"]}


def get_capstone_arch(arch: str, mode: str):
    """Map arch/mode strings to capstone constants."""
    if arch == "x86":
        if mode == "16":
            return Cs(CS_ARCH_X86, CS_MODE_16)
        elif mode == "32":
            return Cs(CS_ARCH_X86, CS_MODE_32)
        elif mode == "64":
            return Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == "arm":
        if mode == "arm":
            return Cs(CS_ARCH_ARM, CS_MODE_ARM)
        elif mode == "thumb":
            return Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    elif arch == "arm64":
        return Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    elif arch == "mips":
        if mode == "32":
            return Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
        elif mode == "64":
            return Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN)
    # Default
    return Cs(CS_ARCH_X86, CS_MODE_32)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
