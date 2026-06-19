const fs = require('fs')
const path = require('path')
const AstUtil = require('../../../util/ast-util')
const Config = require('../../../config')

type CcecDecision = {
  enabled: boolean
  matched: boolean
  action: 'none' | 'force' | 'suppress'
  reason: string
  sourceLine?: number
  virtualSink?: boolean
  finalSink?: string
  sinkAttribute?: string
  traces?: any[]
}

let cachedPath = ''
let cachedCcec: any = null

function loadCcec(): any {
  const ccecPath = Config.lapisCcecFile
  if (!ccecPath) return null
  if (cachedCcec && cachedPath === ccecPath) return cachedCcec
  try {
    cachedPath = ccecPath
    cachedCcec = JSON.parse(fs.readFileSync(ccecPath, 'utf8'))
    return cachedCcec
  } catch (error) {
    cachedCcec = null
    return null
  }
}

function reset(): void {
  cachedPath = ''
  cachedCcec = null
}

function pretty(node: any): string {
  try {
    return AstUtil.prettyPrint(node)
  } catch (error) {
    return ''
  }
}

function textMatches(text: string, needle: string): boolean {
  if (!text || !needle) return false
  if (text === needle || text.includes(needle) || needle.includes(text)) return true
  const last = needle.split('.').pop() || needle
  return text === last || text.includes(last)
}

function strictSymbolMatches(actual: string, expected: string | undefined): boolean {
  if (!actual || !expected) return false
  return actual === expected || actual.endsWith(`.${expected}`) || expected.endsWith(`.${actual}`)
}

function generatedFactoryMatches(fsig: string, edge: any): boolean {
  if (!fsig || !edge) return false
  if (fsig === '_make_method') return false
  const callee = String(edge.callee || '')
  return callee.includes(`${fsig}.<generated`) || callee.includes(`.${fsig}.<generated`)
}

function edgeMatchesSink(edge: any, sinkRule: any, callText: string): boolean {
  const fsig = sinkRule?.fsig || ''
  if (!fsig && !callText) return false
  if (strictSymbolMatches(fsig, edge.caller) || strictSymbolMatches(fsig, edge.callee)) return true
  if (generatedFactoryMatches(fsig, edge)) return true
  return typeof edge.callsite === 'string' && [fsig, callText].filter(Boolean).some((haystack) => textMatches(haystack, edge.callsite))
}

function isVirtualSinkEdge(edge: any, ccec?: any): boolean {
  if (!edge) return false
  const joinedEvidence = Array.isArray(edge.evidence) ? edge.evidence.join('\n') : ''
  const joinedGuards = Array.isArray(edge.guards) ? edge.guards.join('\n') : ''
  const direct = (
    edge.callee_kind === 'builtin_sink' &&
    (String(edge.caller || '').includes('<generated') ||
      joinedEvidence.includes('inner function') ||
      joinedEvidence.includes('_make_method') ||
      joinedGuards.includes('generated'))
  )
  if (direct) return true
  const edges = Array.isArray(ccec?.candidate_edges) ? ccec.candidate_edges : []
  return (
    edge.callee_kind === 'materialized_factory_method' &&
    edges.some((next: any) => next.callee_kind === 'builtin_sink' && next.caller === edge.callee)
  )
}

function edgeMatchesVirtualBoundary(edge: any, ccec: any, sinkRule: any, callText: string): boolean {
  const fsig = sinkRule?.fsig || ''
  if (!isVirtualSinkEdge(edge, ccec)) return false
  if (generatedFactoryMatches(fsig, edge)) return true
  if (fsig === 'array_callback' && edge.callee_kind === 'materialized_factory_method') return true
  if (fsig === '_make_method' && callText.includes('"__array__"')) return true
  if (callText && typeof edge.callsite === 'string' && textMatches(callText, edge.callsite)) return true
  return false
}

function chainEdges(ccec: any, edge: any): any[] {
  const edges = Array.isArray(ccec?.candidate_edges) ? ccec.candidate_edges : []
  const next = edges.find((candidate: any) => candidate.caller === edge?.callee && candidate.callee_kind === 'builtin_sink')
  return next ? [edge, next] : [edge]
}

function finalSinkFromChain(ccec: any, edge: any): string | undefined {
  const chain = chainEdges(ccec, edge)
  const finalEdge = chain[chain.length - 1]
  return finalEdge?.callee_kind === 'builtin_sink' ? finalEdge.callee : undefined
}

function buildTraces(edge: any, node: any, ccec?: any): any[] {
  const chain = chainEdges(ccec, edge)
  const evidence = chain.flatMap((item: any) => (Array.isArray(item.evidence) ? item.evidence : []))
  const traces: any[] = []
  if (evidence.length > 0) {
    traces.push({
      file: node?.loc?.sourcefile,
      line: node?.loc?.start?.line,
      node,
      tag: 'SOURCE: ',
      affectedNodeName: `LAPIS CCEC source/frontier: ${evidence[0]}`,
    })
  }
  for (const chainEdge of chain) {
    traces.push({
      file: node?.loc?.sourcefile,
      line: node?.loc?.start?.line,
      node,
      tag: 'CALL EDGE: ',
      affectedNodeName: `LAPIS CCEC add_call_edge ${chainEdge.caller} -> ${chainEdge.callee}`,
    })
  }
  if (edge.callsite) {
    traces.push({
      file: node?.loc?.sourcefile,
      line: node?.loc?.start?.line,
      node,
      tag: 'CALLSITE: ',
      affectedNodeName: edge.callsite,
    })
  }
  const finalEvidence = evidence[evidence.length - 1]
  if (finalEvidence) {
    traces.push({
      file: node?.loc?.sourcefile,
      line: node?.loc?.start?.line,
      node,
      tag: 'SINK: ',
      affectedNodeName: `LAPIS CCEC final sink evidence: ${finalEvidence}`,
    })
  }
  return traces
}

function edgeMatchesBoundary(edge: any, ccec: any, callText: string): boolean {
  if (!isVirtualSinkEdge(edge, ccec)) return false
  const boundary = edge.boundary_callsite || edge.boundary || edge.frontier_callsite
  if (typeof boundary === 'string' && textMatches(callText, boundary)) return true
  return typeof edge.callsite === 'string' && textMatches(callText, edge.callsite)
}

function evaluatePythonBoundary(node: any): CcecDecision {
  const ccec = loadCcec()
  if (!ccec) {
    return { enabled: false, matched: false, action: 'none', reason: 'ccec disabled' }
  }
  const edges = Array.isArray(ccec.candidate_edges) ? ccec.candidate_edges : []
  const callText = pretty(node)
  const matched = edges.find((edge: any) => edgeMatchesBoundary(edge, ccec, callText))
  let decision: CcecDecision
  if (matched) {
    decision = {
      enabled: true,
      matched: true,
      action: 'force',
      reason: `ccec virtual boundary ${matched.edge_id || matched.caller}`,
      sourceLine: node?.loc?.start?.line,
      virtualSink: true,
      finalSink: finalSinkFromChain(ccec, matched),
      sinkAttribute: `LAPIS CCEC virtual sink: ${finalSinkFromChain(ccec, matched) || 'unknown'}`,
      traces: buildTraces(matched, node, ccec),
    }
  } else {
    decision = {
      enabled: true,
      matched: false,
      action: 'none',
      reason: 'no ccec boundary matched current call',
    }
  }
  appendDiagnostics(decision, node, { fsig: decision.finalSink || '<ccec-boundary>' }, matched)
  return decision
}

function evaluatePythonSink(node: any, rule: any): CcecDecision {
  const ccec = loadCcec()
  if (!ccec) {
    return { enabled: false, matched: false, action: 'none', reason: 'ccec disabled' }
  }
  const edges = Array.isArray(ccec.candidate_edges) ? ccec.candidate_edges : []
  const callText = pretty(node)
  const matched = edges.find((edge: any) => edgeMatchesSink(edge, rule, callText))
    || edges.find((edge: any) => edgeMatchesVirtualBoundary(edge, ccec, rule, callText))
  let decision: CcecDecision
  if (matched) {
    decision = {
      enabled: true,
      matched: true,
      action: 'force',
      reason: `ccec repaired call edge ${matched.edge_id || matched.caller}`,
      sourceLine: node?.loc?.start?.line,
      virtualSink: isVirtualSinkEdge(matched, ccec),
      finalSink: finalSinkFromChain(ccec, matched) || matched.callee,
      traces: buildTraces(matched, node, ccec),
    }
  } else {
    decision = {
      enabled: true,
      matched: false,
      action: 'none',
      reason: 'no ccec edge matched current sink',
    }
  }
  appendDiagnostics(decision, node, rule, matched)
  return decision
}

function appendDiagnostics(decision: CcecDecision, node: any, rule: any, edge: any): void {
  if (!Config.reportDir) return
  try {
    fs.mkdirSync(Config.reportDir, { recursive: true })
    const diagnostic = {
      file: node?.loc?.sourcefile,
      line: node?.loc?.start?.line,
      sink: rule?.fsig,
      action: decision.action,
      matched: decision.matched,
      reason: decision.reason,
      edge: edge || null,
    }
    fs.appendFileSync(
      path.join(Config.reportDir, 'lapis-ccec-diagnostics.jsonl'),
      JSON.stringify(diagnostic) + '\n',
      'utf8'
    )
  } catch (error) {
    // Diagnostics must never affect analysis.
  }
}

module.exports = {
  evaluatePythonBoundary,
  evaluatePythonSink,
  reset,
}
