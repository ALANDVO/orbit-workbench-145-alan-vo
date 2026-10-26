import '@testing-library/jest-dom'
import { vi } from 'vitest'

// Mock axios
vi.mock('axios', () => ({
  default: {
    post: vi.fn(),
    get: vi.fn(),
    isAxiosError: vi.fn(() => false),
  },
}))
