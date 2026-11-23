/** Tests for the pure helpers behind the monitoring dashboard. */
import { formatBytes } from '~/utils/format'
import { scanResultsToCsv } from '~/utils/scanResults'
import {
  conversationsOption,
  protocolOption,
  stateOption,
  topTalkersOption,
  trendOption,
} from '~/utils/monitoringCharts'

const flow = (ip, dst, overrides = {}) => ({
  ts: 100,
  'id.orig_h': ip,
  'id.resp_h': dst,
  proto: 'tcp',
  conn_state: 'SF',
  orig_bytes: 10,
  resp_bytes: 5,
  ...overrides,
})

describe('formatBytes', () => {
  it.each([
    [0, '0 B'],
    [null, '0 B'],
    [512, '512 B'],
    [1024, '1 KB'],
    [1536, '1.5 KB'],
    [1048576, '1 MB'],
  ])('%s -> %s', (input, expected) => {
    expect(formatBytes(input)).toBe(expected)
  })
})

describe('trendOption', () => {
  it('sorts points by time without changing the input', () => {
    const stats = [flow('a', 'b', { ts: 200, orig_bytes: 2 }), flow('a', 'b', { ts: 100, orig_bytes: 1 })]
    const option = trendOption(stats)
    expect(option.series[0].data).toEqual([[100000, 1], [200000, 2]])
    expect(stats[0].ts).toBe(200)
  })

  it('treats missing byte counts as zero', () => {
    const option = trendOption([flow('a', 'b', { orig_bytes: undefined, resp_bytes: 'x' })])
    expect(option.series[0].data[0][1]).toBe(0)
    expect(option.series[1].data[0][1]).toBe(0)
  })
})

describe('pie charts', () => {
  it('counts protocols in upper case, with a fallback', () => {
    const data = protocolOption([flow('a', 'b'), flow('a', 'b'), flow('a', 'b', { proto: '' })]).series[0].data
    expect(data).toEqual([{ name: 'TCP', value: 2 }, { name: 'UNKNOWN', value: 1 }])
  })

  it('counts connection states, with a fallback', () => {
    const data = stateOption([flow('a', 'b'), flow('a', 'b', { conn_state: null })]).series[0].data
    expect(data).toEqual([{ name: 'SF', value: 1 }, { name: 'Unknown', value: 1 }])
  })
})

describe('topTalkersOption', () => {
  it('keeps the five largest senders, biggest last for the bar chart', () => {
    const stats = [1, 2, 3, 4, 5, 6].map((n) => flow(`ip${n}`, 'x', { orig_bytes: n * 10 }))
    const option = topTalkersOption(stats)
    expect(option.yAxis.data).toEqual(['ip2', 'ip3', 'ip4', 'ip5', 'ip6'])
    expect(option.series[0].data).toEqual([20, 30, 40, 50, 60])
  })
})

describe('conversationsOption', () => {
  it('merges flows per direction and skips incomplete rows', () => {
    const stats = [flow('a', 'b'), flow('a', 'b'), flow('b', 'a'), flow('', 'b')]
    const { data, links } = conversationsOption(stats).series[0]
    expect(data.map((n) => n.name).sort()).toEqual(['a', 'b'])
    expect(links).toHaveLength(2)
  })

  it('caps the graph at the 50 busiest links', () => {
    const stats = Array.from({ length: 60 }, (_, i) => flow(`s${i}`, 'd', { orig_bytes: i }))
    expect(conversationsOption(stats).series[0].links).toHaveLength(50)
  })

  it('limits link width to between 1 and 6', () => {
    const widths = conversationsOption([
      flow('a', 'b', { orig_bytes: 1, resp_bytes: 0 }),
      flow('c', 'd', { orig_bytes: 1e9, resp_bytes: 0 }),
    ]).series[0].links.map((l) => l.lineStyle.width)
    expect(widths.sort()).toEqual([1, 6])
  })
})

describe('scanResultsToCsv', () => {
  const header = 'Host,Hostname,Host State,Port,Protocol,Port State,Service,Version,CVEs'

  it('writes one row per port', () => {
    const csv = scanResultsToCsv([{
      host: '10.0.0.1',
      hostname: 'h',
      state: 'up',
      ports: [{ port: 443, protocol: 'tcp', state: 'open', service: 'https', version: 'nginx', cves: ['CVE-1', 'CVE-2'] }],
    }])
    expect(csv).toBe(`${header}\r\n10.0.0.1,h,up,443,tcp,open,https,nginx,CVE-1; CVE-2`)
  })

  it('still writes a row for a host with no open ports', () => {
    expect(scanResultsToCsv([{ host: '10.0.0.1', ports: [] }]).split('\r\n')[1]).toBe('10.0.0.1,,,,,,,,')
  })

  it('quotes values containing commas or quotes', () => {
    const csv = scanResultsToCsv([{ host: 'a,b', ports: [{ version: 'say "hi"' }] }])
    expect(csv.split('\r\n')[1]).toBe('"a,b",,,,,,,"say ""hi""",')
  })
})
