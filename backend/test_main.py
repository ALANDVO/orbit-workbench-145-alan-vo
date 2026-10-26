"""
Tests for Orbit Workbench FastAPI Backend
"""
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_health():
    """Test health endpoint returns ok."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "0.1.0"


def test_upload_binary():
    """Test binary upload endpoint."""
    # Create a simple test binary (x86 NOP sled)
    test_binary = b"\x90" * 100  # 100 NOPs
    
    response = client.post(
        "/api/upload",
        files={"file": ("test.bin", test_binary, "application/octet-stream")}
    )
    assert response.status_code == 200
    data = response.json()
    assert "file_id" in data
    assert data["filename"] == "test.bin"
    assert data["size"] == 100
    assert data["message"] == "Binary uploaded successfully"
    
    return data["file_id"]


def test_disassemble_x86_32():
    """Test disassembly of x86 32-bit code."""
    file_id = test_upload_binary()
    
    response = client.get(f"/api/disasm/{file_id}?arch=x86&mode=32&count=10")
    assert response.status_code == 200
    data = response.json()
    # assert data["file_id"] == file_id  # not in response
    assert data["arch"] == "x86"
    assert data["mode"] == "32"
    assert len(data["instructions"]) > 0
    
    # First instruction should be NOP
    first_insn = data["instructions"][0]
    assert first_insn["mnemonic"] == "nop"
    assert first_insn["address"] == 0x1000


def test_disassemble_x86_64():
    """Test disassembly of x86 64-bit code."""
    file_id = test_upload_binary()
    
    response = client.get(f"/api/disasm/{file_id}?arch=x86&mode=64&count=10")
    assert response.status_code == 200
    data = response.json()
    assert data["mode"] == "64"


def test_disassemble_arm():
    """Test disassembly of ARM code."""
    # ARM test binary (MOV R0, #1; BX LR)
    arm_binary = b"\x01\x00\xa0\xe3\x1e\xff\x2f\xe1"
    
    response = client.post(
        "/api/upload",
        files={"file": ("test_arm.bin", arm_binary, "application/octet-stream")}
    )
    assert response.status_code == 200
    file_id = response.json()["file_id"]
    
    response = client.get(f"/api/disasm/{file_id}?arch=arm&mode=32&count=5")
    assert response.status_code == 200
    data = response.json()
    assert data["arch"] == "arm"
    assert len(data["instructions"]) > 0


def test_binary_info():
    """Test binary info endpoint."""
    file_id = test_upload_binary()
    
    response = client.get(f"/api/info/{file_id}")
    assert response.status_code == 200
    data = response.json()
    # assert data["file_id"] == file_id  # not in response
    assert data["filename"] == "test.bin"
    assert data["size"] == 100


def test_not_found():
    """Test 404 for non-existent binary."""
    response = client.get("/api/disasm/non-existent-id")
    assert response.status_code == 404
    
    response = client.get("/api/info/non-existent-id")
    assert response.status_code == 404


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
