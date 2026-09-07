import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { forceCollide } from 'd3-force'
import { mockTopology, deriveMaxCvss } from '../data/mockTopology'

// CVSS v3 qualitative severity bands.
const SEVERITY_BANDS = [
  { label: 'Critical', min: 9.0, color: '#ef4444' },
  { label: 'High', min: 7.0, color: '#f97316' },
  { label: 'Medium', min: 4.0, color: '#eab308' },
  { label: 'Low', min: 0.1, color: '#38bdf8' },
  { label: 'None', min: 0, color: '#64748b' },
]

function severityFor(score) {
  return SEVERITY_BANDS.find((band) => score >= band.min) ?? SEVERITY_BANDS.at(-1)
}

// Higher CVSS draws a bigger node, clamped so low-risk hosts stay visible.
function radiusFor(score) {
  return 5 + (score / 10) * 7
}

function TopologyMap({ data = mockTopology }) {
  const containerRef = useRef(null)
  const graphRef = useRef(null)
  const [size, setSize] = useState({ width: 0, height: 460 })
  const [selected, setSelected] = useState(null)
  const [hovered, setHovered] = useState(null)

  // react-force-graph mutates the graph it is given (adds x/y/vx/vy and swaps
  // link endpoints for node refs), so hand it a clone and keep `data` pristine.
  const graphData = useMemo(
    () => ({
      nodes: data.nodes.map((node) => ({ ...node, maxCvss: deriveMaxCvss(node) })),
      links: data.links.map((link) => ({ ...link })),
    }),
    [data],
  )

  // ForceGraph2D needs explicit pixel dimensions — track the container instead
  // of hardcoding, so the canvas reflows with the layout.
  useEffect(() => {
    const element = containerRef.current
    if (!element) return undefined

    const observer = new ResizeObserver(([entry]) => {
      const { width } = entry.contentRect
      setSize({ width, height: width < 640 ? 340 : 460 })
    })

    observer.observe(element)
    return () => observer.disconnect()
  }, [])

  const drawNode = useCallback(
    (node, ctx, globalScale) => {
      const score = node.maxCvss ?? 0
      const { color } = severityFor(score)
      const radius = radiusFor(score)
      const isActive = selected?.id === node.id || hovered?.id === node.id

      // Halo on the active node.
      if (isActive) {
        ctx.beginPath()
        ctx.arc(node.x, node.y, radius + 4, 0, 2 * Math.PI)
        ctx.fillStyle = `${color}33`
        ctx.fill()
      }

      ctx.beginPath()
      ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI)
      ctx.fillStyle = color
      ctx.fill()
      ctx.lineWidth = isActive ? 2 / globalScale : 1 / globalScale
      ctx.strokeStyle = isActive ? '#e2e8f0' : '#0b1220'
      ctx.stroke()

      // Hide labels when zoomed far out, otherwise they collide into mush.
      if (globalScale > 0.7) {
        const fontSize = 11 / globalScale
        ctx.font = `${fontSize}px ui-monospace, SFMono-Regular, Menlo, monospace`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'top'
        ctx.fillStyle = '#cbd5e1'
        ctx.fillText(node.id, node.x, node.y + radius + 2)
      }
    },
    [selected, hovered],
  )

  // Keep the clickable area in sync with the drawn radius.
  const drawNodePointerArea = useCallback((node, color, ctx) => {
    ctx.beginPath()
    ctx.arc(node.x, node.y, radiusFor(node.maxCvss ?? 0) + 3, 0, 2 * Math.PI)
    ctx.fillStyle = color
    ctx.fill()
  }, [])

  // Default forces pack the nodes into an overlapping clump at this scale.
  // Charge/link spread them out; the collide force is the guarantee — it gives
  // every node a hard radius no neighbour can enter, so labels stay readable
  // regardless of how the other forces settle.
  useEffect(() => {
    const graph = graphRef.current
    if (!graph) return

    graph.d3Force('charge')?.strength(-180).distanceMax(400)
    graph.d3Force('link')?.distance(70)
    graph.d3Force(
      'collide',
      forceCollide((node) => radiusFor(node.maxCvss ?? 0) + 16).strength(1),
    )
    graph.d3ReheatSimulation()
  }, [graphData])

  const handleFit = useCallback(() => {
    graphRef.current?.zoomToFit(400, 70)
  }, [])

  const totalCves = graphData.nodes.reduce((sum, node) => sum + (node.cves?.length ?? 0), 0)

  return (
    <section className="rounded-lg border border-slate-800 bg-[#0d1526] font-mono shadow-lg shadow-black/30">
      <div className="flex items-center gap-2 border-b border-slate-800 bg-[#0f172a] px-4 py-2.5">
        <span className="h-2.5 w-2.5 rounded-full bg-red-500/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-amber-400/70" />
        <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/70" />
        <span className="ml-2 truncate text-xs tracking-wide text-slate-500">
          reconcore@topology — network map
        </span>
      </div>

      <div className="p-4 sm:p-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h3 className="text-base font-semibold tracking-tight text-slate-100">
              <span className="mr-2 text-emerald-400">$</span>Network Topology
            </h3>
            <p className="mt-1 text-xs leading-relaxed text-slate-500">
              {graphData.nodes.length} hosts · {graphData.links.length} links ·{' '}
              {totalCves} CVEs. Node size and color track the highest CVSS on each
              host.
            </p>
          </div>

          <button
            type="button"
            onClick={handleFit}
            className="shrink-0 self-start rounded-md border border-slate-700 bg-[#080e1a] px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-slate-600 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400"
          >
            Fit to view
          </button>
        </div>

        {/* Legend */}
        <ul className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2">
          {SEVERITY_BANDS.map((band) => (
            <li key={band.label} className="flex items-center gap-1.5 text-[11px] text-slate-500">
              <span
                aria-hidden="true"
                className="h-2.5 w-2.5 rounded-full"
                style={{ backgroundColor: band.color }}
              />
              {band.label}
            </li>
          ))}
        </ul>

        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[1fr_260px]">
          {/* Canvas */}
          <div
            ref={containerRef}
            className="min-w-0 overflow-hidden rounded-md border border-slate-800 bg-[#080e1a]"
            style={{ height: size.height }}
          >
            {size.width > 0 && (
              <ForceGraph2D
                ref={graphRef}
                graphData={graphData}
                width={size.width}
                height={size.height}
                backgroundColor="#080e1a"
                nodeRelSize={6}
                nodeCanvasObject={drawNode}
                nodePointerAreaPaint={drawNodePointerArea}
                nodeLabel={(node) => `${node.id} — ${node.hostname}`}
                linkColor={() => '#475569'}
                linkWidth={1.5}
                linkDirectionalParticles={2}
                linkDirectionalParticleWidth={2}
                linkDirectionalParticleColor={() => '#22d3ee'}
                onNodeClick={(node) => setSelected(node)}
                onNodeHover={(node) => setHovered(node)}
                onBackgroundClick={() => setSelected(null)}
                cooldownTicks={100}
                onEngineStop={handleFit}
              />
            )}
          </div>

          {/* Detail panel */}
          <aside className="min-w-0 rounded-md border border-slate-800 bg-[#080e1a] p-3.5">
            {selected ? (
              <div>
                <p className="text-sm font-semibold text-slate-100">{selected.id}</p>
                <p className="mt-0.5 text-xs text-slate-500">
                  {selected.hostname} · {selected.os}
                </p>

                <p className="mt-3 text-[11px] uppercase tracking-[0.18em] text-slate-600">
                  Open ports
                </p>
                <ul className="mt-1.5 space-y-1">
                  {selected.ports?.map((port) => (
                    <li key={`${port.protocol}-${port.port}`} className="text-xs text-slate-400">
                      <span className="text-emerald-400">{port.port}</span>/{port.protocol}{' '}
                      <span className="text-slate-500">
                        {port.service}
                        {port.version ? ` ${port.version}` : ''}
                      </span>
                    </li>
                  ))}
                </ul>

                <p className="mt-3 text-[11px] uppercase tracking-[0.18em] text-slate-600">
                  Vulnerabilities
                </p>
                <ul className="mt-1.5 space-y-1.5">
                  {selected.cves?.length ? (
                    selected.cves.map((cve) => (
                      <li key={cve.cveId} className="text-xs">
                        <span className="break-all text-slate-300">{cve.cveId}</span>{' '}
                        <span style={{ color: severityFor(cve.score).color }}>{cve.score}</span>
                      </li>
                    ))
                  ) : (
                    <li className="text-xs text-slate-600">None recorded.</li>
                  )}
                </ul>
              </div>
            ) : (
              <p className="text-xs leading-relaxed text-slate-600">
                Click a node to inspect its open ports and CVE findings. Drag to
                reposition, scroll to zoom.
              </p>
            )}
          </aside>
        </div>
      </div>
    </section>
  )
}

export default TopologyMap
