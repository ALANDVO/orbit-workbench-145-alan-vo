import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from './App'

// Mock axios - must be hoisted, so define inline with proper resolved values
vi.mock('axios', () => ({
  default: {
    post: vi.fn().mockResolvedValue({ data: { file_id: 'test-id', filename: 'test.bin', size: 100, message: 'OK' } }),
    get: vi.fn().mockResolvedValue({ data: { file_id: 'test-id', instructions: [], total_count: 0, arch: 'x86', mode: '32' } }),
    isAxiosError: vi.fn(() => false),
  },
}))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false },
    mutations: { retry: false },
  },
})

function renderApp() {
  return render(
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  )
}

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the header', () => {
    renderApp()
    expect(screen.getByText('Orbit Workbench')).toBeInTheDocument()
    expect(screen.getByText('Reverse Engineering Workbench')).toBeInTheDocument()
  })

  it('renders upload section', () => {
    renderApp()
    expect(screen.getByText('Binary Upload')).toBeInTheDocument()
    expect(screen.getByLabelText('Choose File')).toBeInTheDocument()
  })

  it('renders disassembly section', () => {
    renderApp()
    expect(screen.getByText('Disassembly')).toBeInTheDocument()
    expect(screen.getByText('Upload a binary to begin disassembly')).toBeInTheDocument()
  })

  it('shows file name when file is selected', () => {
    renderApp()
    const input = screen.getByLabelText('Choose File') as HTMLInputElement
    const file = new File(['test'], 'test.bin', { type: 'application/octet-stream' })
    
    fireEvent.change(input, { target: { files: [file] } })
    
    expect(screen.getByText('test.bin (4 bytes)')).toBeInTheDocument()
  })
})
