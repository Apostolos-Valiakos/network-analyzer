/** Tests for utils/realtime.js and utils/history.js. */
import { base64Size, generateSessionId, ipv4Endpoints } from '~/utils/realtime'
import {
  clusterHeaders,
  formatConfidence,
  formatDate,
  formatSize,
  pcapHeaders,
  statusColor,
} from '~/utils/history'

// Ethernet header (IPv4 EtherType) + 20-byte IPv4 header from 10.0.0.1 to 192.168.1.20
function ipv4Frame() {
  const bytes = new Uint8Array(34)
  bytes[12] = 0x08
  bytes[13] = 0x00
  bytes.set([10, 0, 0, 1], 26)
  bytes.set([192, 168, 1, 20], 30)
  return btoa(String.fromCharCode(...bytes))
}

describe('utils/realtime', () => {
  test('reads the IPv4 source and destination', () => {
    expect(ipv4Endpoints(ipv4Frame())).toEqual({ src: '10.0.0.1', dst: '192.168.1.20' })
  })

  test('ignores non-IPv4, short and undecodable frames', () => {
    const arp = new Uint8Array(42)
    arp[12] = 0x08
    arp[13] = 0x06
    expect(ipv4Endpoints(btoa(String.fromCharCode(...arp)))).toBeNull()
    expect(ipv4Endpoints(btoa('short'))).toBeNull()
    expect(ipv4Endpoints('%%% not base64 %%%')).toBeNull()
  })

  test('estimates the decoded size and makes unique session ids', () => {
    expect(base64Size('AAAA')).toBe(3)
    const a = generateSessionId()
    expect(a).toMatch(/^session_/)
    expect(generateSessionId()).not.toBe(a)
  })
})

describe('utils/history', () => {
  test('formats sizes, confidences and empty values', () => {
    expect(formatSize(0)).toBe('—')
    expect(formatSize(512)).toBe('512 B')
    expect(formatSize(2048)).toBe('2.0 KB')
    expect(formatSize(3 * 1048576)).toBe('3.0 MB')
    expect(formatConfidence(0.873)).toBe('87%')
    expect(formatConfidence(null)).toBe('—')
    expect(formatDate(null)).toBe('—')
  })

  test('maps statuses to colours', () => {
    expect(statusColor('completed')).toBe('success')
    expect(statusColor('ERROR')).toBe('error')
    expect(statusColor('PROCESSING')).toBe('warning')
    expect(statusColor('something')).toBe('grey')
    expect(statusColor(null)).toBe('grey')
  })

  test('admins also see the owner column', () => {
    expect(pcapHeaders(false).map((h) => h.value)).toEqual([
      'original_filename', 'upload_time', 'file_size', 'status', 'actions',
    ])
    expect(pcapHeaders(true).map((h) => h.value)).toEqual([
      'original_filename', 'upload_time', 'file_size', 'status', 'username', 'actions',
    ])
    expect(clusterHeaders(true).map((h) => h.value)).toEqual([
      'original_filename', 'created_at', 'username', 'actions',
    ])
  })
})
