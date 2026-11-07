import { useState, useCallback } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import axios from 'axios'

const API_BASE = '/api'

interface UploadResponse {
  file_id: string
  filename: string
  size: number
  message: string
}

interface Instruction {
  address: number
  mnemonic: string
  op_str: string
  bytes: string
}

interface DisasmResponse {
  file_id: string
  instructions: Instruction[]
  total_count: number
  arch: string
  mode: string
}

interface VtableEntry {
  address: number
  function_name: string
  index: number
}

interface Vtable {
  address: number
  size: number
  entries: VtableEntry[]
  class_name: string | null
}

interface VtableAnalysisResponse {
  file_id: string
  vtables: Vtable[]
  resolved_calls: Record<string, unknown>[]
}


function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileId, setFileId] = useState<string | null>(null)
  const [arch, setArch] = useState<'x86' | 'arm' | 'mips' | 'mipsbe'>('x86')
  const [mode, setMode] = useState<'16' | '32' | '64'>('32')
  const [offset, setOffset] = useState(0)
  const [count, setCount] = useState(100)
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)

  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      const formData = new FormData()
      formData.append('file', file)
      const response = await axios.post<UploadResponse>(`${API_BASE}/upload`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      return response.data
    },
    onSuccess: (data) => {
      setFileId(data.file_id)
      setInfo(`Uploaded: ${data.filename} (${data.size} bytes)`)
      setError(null)
    },
    onError: (err: unknown) => {
      if (axios.isAxiosError(err)) {
        setError(err.response?.data?.detail || err.message)
      } else {
        setError('Upload failed')
      }
    },
  })

  const { data: disasmData, isLoading, refetch } = useQuery({
    queryKey: ['disasm', fileId, arch, mode, offset, count],
    queryFn: async () => {
      if (!fileId) return null
      const response = await axios.get<DisasmResponse>(`${API_BASE}/disasm/${fileId}`, {
        params: { arch, mode, offset, count },
      })
      return response.data
    },
  })

  const { data: vtableData, isLoading: vtableLoading, refetch: refetchVtable } = useQuery({
    queryKey: ['vtable', fileId, arch, mode],
    queryFn: async () => {
      if (!fileId) return null
      const response = await axios.get<VtableAnalysisResponse>(`${API_BASE}/vtable/${fileId}`, {
        params: { arch, mode },
      })
      return response.data
    },
    enabled: !!fileId,
  })

  const handleVtableAnalysis = useCallback(() => {
    refetchVtable()
  }, [refetchVtable])

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0])
      setError(null)
    }
  }, [])

  const handleUpload = useCallback(() => {
    if (selectedFile) {
      uploadMutation.mutate(selectedFile)
    }
  }, [selectedFile, uploadMutation])

  const handleDisasm = useCallback(() => {
    refetch()
  }, [refetch])

  return (
    <div className="app">
      <header className="header">
        <h1>Orbit Workbench</h1>
        <span style={{ fontSize: '0.75rem', color: '#808080' }}>Reverse Engineering Workbench</span>
      </header>

      <main className="main-content">
        <section className="upload-section">
          <h2>Binary Upload</h2>
          <div className="file-input-wrapper">
            <input
              type="file"
              id="file-input"
              className="file-input"
              accept=".bin,.exe,.dll,.so,.elf,.o,.obj"
              onChange={handleFileSelect}
              disabled={uploadMutation.isPending}
            />
            <label htmlFor="file-input" className="file-input-label">
              {uploadMutation.isPending ? 'Uploading...' : 'Choose File'}
            </label>
            {selectedFile && (
              <span className="selected-file">{selectedFile.name} ({selectedFile.size} bytes)</span>
            )}
            <button
              className="upload-btn"
              onClick={handleUpload}
              disabled={!selectedFile || uploadMutation.isPending}
            >
              Upload
            </button>
          </div>
        </section>

        {error && <div className="error">{error}</div>}
        {info && <div className="info">{info}</div>}

        <section className="disasm-section">
          <div className="disasm-header">
            <h2>Disassembly</h2>
            <div className="disasm-controls">
              <select
                className="disasm-select"
                value={arch}
                onChange={(e) => setArch(e.target.value as typeof arch)}
              >
                <option value="x86">x86</option>
                <option value="arm">ARM</option>
                <option value="mips">MIPS (LE)</option>
                <option value="mipsbe">MIPS (BE)</option>
              </select>
              <select
                className="disasm-select"
                value={mode}
                onChange={(e) => setMode(e.target.value as typeof mode)}
              >
                <option value="16">16-bit</option>
                <option value="32">32-bit</option>
                <option value="64">64-bit</option>
              </select>
              <input
                type="number"
                className="disasm-select"
                style={{ width: '80px' }}
                value={offset}
                onChange={(e) => setOffset(parseInt(e.target.value) || 0)}
                min="0"
                placeholder="Offset"
              />
              <input
                type="number"
                className="disasm-select"
                style={{ width: '80px' }}
                value={count}
                onChange={(e) => setCount(parseInt(e.target.value) || 100)}
                min="1"
                max="1000"
                placeholder="Count"
              />
              <button
                className="upload-btn"
                onClick={handleDisasm}
                disabled={!fileId || isLoading}
                style={{ padding: '4px 12px' }}
              >
                {isLoading ? 'Loading...' : 'Disassemble'}
              </button>
            </div>
          </div>

          <div className="disasm-table-container">
            {fileId ? (
              isLoading ? (
                <div className="loading">Disassembling...</div>
              ) : disasmData && disasmData.instructions.length > 0 ? (
                <table className="disasm-table">
                  <thead>
                    <tr>
                      <th className="address">Address</th>
                      <th className="bytes">Bytes</th>
                      <th className="mnemonic">Mnemonic</th>
                      <th className="operands">Operands</th>
                    </tr>
                  </thead>
                  <tbody>
                    {disasmData.instructions.map((insn, idx) => (
                      <tr key={idx}>
                        <td className="address">0x{insn.address.toString(16).padStart(8, '0')}</td>
                        <td className="bytes">{insn.bytes}</td>
                        <td className="mnemonic">{insn.mnemonic}</td>
                        <td className="operands">{insn.op_str}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="loading">No instructions found. Try different architecture/mode settings.</div>
              )
            ) : (
              <div className="loading">Upload a binary to begin disassembly</div>
            )}
          </div>
        </section>

        <section className="vtable-section">
          <div className="vtable-header">
            <h2>Vtable Analysis</h2>
            <button
              className="upload-btn"
              onClick={handleVtableAnalysis}
              disabled={!fileId || vtableLoading}
              style={{ padding: '4px 12px' }}
            >
              {vtableLoading ? 'Analyzing...' : 'Analyze Vtables'}
            </button>
          </div>

          <div className="vtable-container">
            {fileId ? (
              vtableLoading ? (
                <div className="loading">Analyzing vtables...</div>
              ) : vtableData && vtableData.vtables.length > 0 ? (
                <div className="vtable-list">
                  {vtableData.vtables.map((vtable, vtIdx) => (
                    <div key={vtIdx} className="vtable-card">
                      <div className="vtable-header-row">
                        <span className="vtable-class">{vtable.class_name || `Vtable at 0x${vtable.address.toString(16)}`}</span>
                        <span className="vtable-address">Address: 0x{vtable.address.toString(16)}</span>
                        <span className="vtable-size">Size: {vtable.size} bytes ({vtable.entries.length} entries)</span>
                      </div>
                      <table className="vtable-table">
                        <thead>
                          <tr>
                            <th className="vtable-index">Index</th>
                            <th className="vtable-func-addr">Function Address</th>
                            <th className="vtable-func-name">Function Name</th>
                          </tr>
                        </thead>
                        <tbody>
                          {vtable.entries.map((entry, eIdx) => (
                            <tr key={eIdx}>
                              <td className="vtable-index">{entry.index}</td>
                              <td className="vtable-func-addr">0x{entry.address.toString(16).padStart(8, '0')}</td>
                              <td className="vtable-func-name">{entry.function_name}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ))}
                </div>
              ) : vtableData && vtableData.resolved_calls.length > 0 ? (
                <div className="resolved-calls">
                  <h3>Resolved Indirect Calls</h3>
                  <table className="vtable-table">
                    <thead>
                      <tr>
                        <th className="address">Address</th>
                        <th className="instruction">Instruction</th>
                        <th className="note">Note</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vtableData.resolved_calls.map((call, idx) => (
                        <tr key={idx}>
                          <td className="address">0x{call.address.toString(16).padStart(8, '0')}</td>
                          <td className="instruction">{call.instruction}</td>
                          <td className="note">{call.note}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="loading">No vtables found. Click "Analyze Vtables" to scan.</div>
              )
            ) : (
              <div className="loading">Upload a binary to begin vtable analysis</div>
            )}
          </div>
        </section>
      </main>
    </div>
  )
}

export default App
