const fs = require('fs')
const path = require('path')
const AstUtil = require('../../../util/ast-util')
const Config = require('../../../config')

type CtpcDecision = {
  enabled: boolean
  matched: boolean
  action: 'none' | 'force' | 'suppress'
  reason: string
  sourceLine?: number
}

type AccessPathFact = {
  symbol: string
  accessPath: string
  riskKind?: string
  sourceLine?: number
  evidence: string
}

type FileFacts = {
  taintedSymbols: Map<string, AccessPathFact>
  taintedDictKeys: Map<string, AccessPathFact>
  preservedDictKeys: Map<string, AccessPathFact>
  sqlStructureVars: Map<string, AccessPathFact>
  killGuards: AccessPathFact[]
  scannedGuardLines: Set<number>
}

type FactMapName = 'taintedSymbols' | 'taintedDictKeys' | 'preservedDictKeys' | 'sqlStructureVars'

let cachedPath = ''
let cachedCtpc: any = null
const fileFacts = new Map<string, FileFacts>()

function emptyFacts(): FileFacts {
  return {
    taintedSymbols: new Map(),
    taintedDictKeys: new Map(),
    preservedDictKeys: new Map(),
    sqlStructureVars: new Map(),
    killGuards: [],
    scannedGuardLines: new Set(),
  }
}

function factsFor(file: string | undefined): FileFacts {
  const key = file || '<unknown>'
  if (!fileFacts.has(key)) fileFacts.set(key, emptyFacts())
  return fileFacts.get(key)!
}

function allFactScopes(localFacts?: FileFacts): FileFacts[] {
  const scopes = Array.from(fileFacts.values())
  if (!localFacts) return scopes
  return [localFacts, ...scopes.filter((scope) => scope !== localFacts)]
}

function factEntries(
  localFacts: FileFacts,
  mapName: FactMapName
): [string, AccessPathFact][] {
  const entries: [string, AccessPathFact][] = []
  const seen = new Set<string>()
  for (const scope of allFactScopes(localFacts)) {
    for (const [key, fact] of scope[mapName].entries()) {
      if (seen.has(key)) continue
      seen.add(key)
      entries.push([key, fact])
    }
  }
  return entries
}

function lookupFact(
  localFacts: FileFacts,
  mapName: FactMapName,
  key: string | undefined
): AccessPathFact | undefined {
  if (!key) return undefined
  for (const scope of allFactScopes(localFacts)) {
    const fact = scope[mapName].get(key)
    if (fact) return fact
  }
  return undefined
}

function globalFactValues(mapName: FactMapName): AccessPathFact[] {
  const values: AccessPathFact[] = []
  for (const scope of fileFacts.values()) values.push(...scope[mapName].values())
  return values
}

function resetFacts(): void {
  fileFacts.clear()
}

function loadCtpc(): any {
  const ctpcPath = Config.lapisCtpcFile
  if (!ctpcPath) return null
  if (cachedCtpc && cachedPath === ctpcPath) return cachedCtpc
  try {
    cachedPath = ctpcPath
    cachedCtpc = JSON.parse(fs.readFileSync(ctpcPath, 'utf8'))
    return cachedCtpc
  } catch (error) {
    cachedCtpc = null
    return null
  }
}

function enabled(): boolean {
  return !!loadCtpc()
}

function pretty(node: any): string {
  try {
    return AstUtil.prettyPrint(node)
  } catch (error) {
    return ''
  }
}

function symbolName(node: any): string | undefined {
  if (!node) return undefined
  if (node.name) return node.name
  if (node.id?.name) return node.id.name
  const text = pretty(node)
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(text) ? text : undefined
}

function lineOf(node: any): number | undefined {
  return node?.loc?.start?.line
}

function isTainted(value: any): boolean {
  return !!value?.taint?.isTaintedRec
}

function hasPattern(event: string, kind: string): boolean {
  return rulesFor(event, kind).length > 0
}

function rulesFor(event: string, kind: string): any[] {
  const ctpc = loadCtpc()
  if (ctpc?.schema_version === 'ctpc.v2') {
    const edges = Array.isArray(ctpc.propagation_edges) ? ctpc.propagation_edges : []
    const summaries = Array.isArray(ctpc.function_summaries) ? ctpc.function_summaries : []
    const upgrades = Array.isArray(ctpc.risk_upgrades) ? ctpc.risk_upgrades : []
    const kills = Array.isArray(ctpc.kill_conditions) ? ctpc.kill_conditions : []
    return [...edges, ...summaries, ...upgrades, ...kills].filter(
      (rule: any) => rule.event === event && rule.pattern?.kind === kind
    )
  }
  const edges = ctpc?.propagation_edges
  const kills = ctpc?.kill_conditions
  if (!Array.isArray(edges)) return [{}]
  const legacyNeedles: Record<string, string[]> = {
    dict_literal_key: ['dict key', 'key position'],
    dict_comprehension_key_preserved: ['dict comprehension', 'items()'],
    percent_mapping_key: ['percent formatting', 'mapping'],
    membership_rejection_guard: ['whitelist', 'rejects dict parameters'],
    missing_mapping_key_fact: ['only used as a value'],
  }
  const needles = legacyNeedles[kind] || [kind]
  const haystacks = [
    ...edges.map((edge: any) => `${edge.kind || ''} ${edge.condition || ''}`.toLowerCase()),
    ...(Array.isArray(kills) ? kills.map((kill: any) => String(kill).toLowerCase()) : []),
  ]
  return haystacks.some((haystack: string) => needles.some((needle: string) => haystack.includes(needle))) ? [{}] : []
}

function riskKind(defaultRisk: string = 'SQL_STRUCTURE'): string {
  const ctpc = loadCtpc()
  return ctpc?.applies_to?.risk_kind || defaultRisk
}

function addFact(map: Map<string, AccessPathFact>, key: string, fact: AccessPathFact): void {
  if (!map.has(key)) map.set(key, fact)
}

function factMapName(factName: string | undefined): FactMapName | undefined {
  if (factName === 'tainted_symbol') return 'taintedSymbols'
  if (factName === 'mapping_key') return 'taintedDictKeys'
  if (factName === 'sql_structure_value') return 'sqlStructureVars'
  return undefined
}

function callExpressionParts(callText: string): { callee: string; args: string[] } | undefined {
  const match = callText.match(/([A-Za-z_][A-Za-z0-9_.]*)\s*\((.*)\)\s*$/)
  if (!match) return undefined
  return {
    callee: match[1],
    args: match[2].split(',').map((arg) => arg.trim()).filter((arg) => arg.length > 0),
  }
}

function calleeMatches(actual: string, expected: string | undefined): boolean {
  if (!expected) return false
  return actual === expected || actual.endsWith(`.${expected}`) || actual.split('.').pop() === expected
}

function factFromCallReturnSummary(facts: FileFacts, callText: string, node: any, evidence: string): AccessPathFact | undefined {
  const call = callExpressionParts(callText)
  if (!call) return undefined
  for (const summary of rulesFor('function_call', 'return_fact_from_argument')) {
    const pattern = summary.pattern || {}
    if (!calleeMatches(call.callee, pattern.callee)) continue
    const argIndex = Number.isInteger(pattern.argument_index) ? pattern.argument_index : 0
    const argName = call.args[argIndex]
    const mapName = factMapName(summary.from?.fact)
    if (!mapName) continue
    const sourceFact = lookupFact(facts, mapName, argName)
    if (!sourceFact) continue
    return {
      symbol: '$return',
      accessPath: summary.to?.access_path || '$return',
      riskKind: summary.to?.risk_kind || sourceFact.riskKind || riskKind(),
      sourceLine: sourceFact.sourceLine || lineOf(node),
      evidence,
    }
  }
  return undefined
}

function recordAssignment(analyzer: any, scope: any, node: any, state: any, info: any): void {
  if (!enabled()) return
  const file = node?.loc?.sourcefile
  const facts = factsFor(file)
  const target = symbolName(node?.left)
  if (!target) return

  const rightText = pretty(node?.right)
  const leftText = pretty(node?.left)
  const evidence = `${leftText} = ${rightText}`

  if (isTainted(info?.rvalue)) {
    addFact(facts.taintedSymbols, target, {
      symbol: target,
      accessPath: target,
      sourceLine: lineOf(node),
      evidence,
    })
  }

  syncPriorGuardFacts(file, facts, lineOf(node))
  recordDictLiteralKey(facts, target, rightText, node, evidence)
  recordDictComprehensionKeyPreserved(facts, target, rightText, node, evidence)
  recordPercentFormatResult(facts, target, info?.rvalue, rightText, node, evidence)
}

function syncPriorGuardFacts(file: string | undefined, facts: FileFacts, upToLine: number | undefined): void {
  if (!file || !upToLine || !fs.existsSync(file)) return
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/)
  for (let index = 0; index < Math.min(lines.length, upToLine - 1); index++) {
    const lineNo = index + 1
    if (facts.scannedGuardLines.has(lineNo)) continue
    const line = lines[index]
    for (const sourceSymbol of facts.taintedSymbols.keys()) {
      const guardPattern = new RegExp(`\\b${sourceSymbol}\\b\\s+not\\s+in\\s+[{([]`)
      if (!guardPattern.test(line)) continue
      facts.killGuards.push({
        symbol: sourceSymbol,
        accessPath: sourceSymbol,
        riskKind: 'SQL_STRUCTURE',
        sourceLine: lineNo,
        evidence: line.trim(),
      })
      facts.scannedGuardLines.add(lineNo)
    }
  }
}

function recordDictLiteralKey(
  facts: FileFacts,
  target: string,
  rightText: string,
  node: any,
  evidence: string
): void {
  if (!hasPattern('assignment', 'dict_literal_key')) return
  for (const [sourceSymbol, sourceFact] of facts.taintedSymbols.entries()) {
    const dictKeyPattern = new RegExp(`[{,]\\s*${sourceSymbol}\\s*:`)
    if (!dictKeyPattern.test(rightText)) continue
    addFact(facts.taintedDictKeys, target, {
      symbol: target,
      accessPath: `${target}.keys()[*]`,
      riskKind: riskKind(),
      sourceLine: sourceFact.sourceLine || lineOf(node),
      evidence,
    })
  }
}

function recordDictComprehensionKeyPreserved(
  facts: FileFacts,
  target: string,
  rightText: string,
  node: any,
  evidence: string
): void {
  if (!hasPattern('assignment', 'dict_comprehension_key_preserved')) return
  for (const [sourceMap, sourceFact] of factEntries(facts, 'taintedDictKeys')) {
    const itemsPattern = new RegExp(`for\\s*\\(\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*,\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\)\\s*in\\s*${sourceMap}\\.items\\s*\\(`)
    const match = rightText.match(itemsPattern)
    if (!match) continue
    const keyVar = match[1]
    const emitsOriginalKey = new RegExp(`[{]\\s*${keyVar}\\s*:`).test(rightText)
    if (!emitsOriginalKey) continue
    addFact(facts.preservedDictKeys, target, {
      symbol: target,
      accessPath: `${target}.keys()[*]`,
      riskKind: sourceFact.riskKind,
      sourceLine: sourceFact.sourceLine || lineOf(node),
      evidence,
    })
  }
}

function recordPercentFormatResult(
  facts: FileFacts,
  target: string,
  rvalue: any,
  rightText: string,
  node: any,
  evidence: string
): void {
  if (!hasPattern('assignment', 'percent_mapping_key')) return
  const operator = rvalue?.operator
  if (operator !== '%' && !/\s%\s/.test(rightText)) return

  const rhs = rvalue?.right
  const rhsName = rhs?.sid || rhs?.qid || symbolName(node?.right?.right) || rightText.split('%').pop()?.trim()
  const rhsCallText = rightText.includes('%') ? rightText.split('%').pop()?.trim() : undefined
  let sourceFact = lookupFact(facts, 'preservedDictKeys', rhsName) || lookupFact(facts, 'taintedDictKeys', rhsName)
  if (!sourceFact) sourceFact = factFromCallReturnSummary(facts, rhsCallText || rhsName, node, evidence)
  if (!sourceFact && rhsCallText !== rhsName) sourceFact = factFromCallReturnSummary(facts, rhsName, node, evidence)
  if (!sourceFact) return

  addFact(facts.sqlStructureVars, target, {
    symbol: target,
    accessPath: target,
    riskKind: riskKind(),
    sourceLine: sourceFact.sourceLine || lineOf(node),
    evidence,
  })
}

function recordBinaryOperation(analyzer: any, scope: any, node: any, state: any, info: any): void {
  if (!enabled()) return
  if (node?.operator !== '%') return
  const file = node?.loc?.sourcefile
  const facts = factsFor(file)
  const rightText = pretty(node?.right)
  const rightName = symbolName(node?.right) || rightText
  if (lookupFact(facts, 'preservedDictKeys', rightName) || lookupFact(facts, 'taintedDictKeys', rightName)) {
    appendDiagnostics(
      {
        enabled: true,
        matched: true,
        action: 'none',
        reason: `ctpc observed percent-format consumer for ${rightName}`,
      },
      node,
      { fsig: '<binary:%>' }
    )
  }
}

function recordIfCondition(analyzer: any, scope: any, node: any, state: any, info: any): void {
  if (!enabled()) return
  const file = node?.loc?.sourcefile
  const facts = factsFor(file)
  const text = pretty(node)
  const operator = String(node?.operator || '').replace(/\s/g, '').toLowerCase()
  const hasNotInGuard = hasPattern('if_condition', 'membership_rejection_guard') &&
    (/\bnot\s*in\b/.test(text) || operator === 'notin' || operator === 'not_in')
  if (!hasNotInGuard) return
  const guardedSymbol = symbolName(node?.left)
  for (const sourceSymbol of facts.taintedSymbols.keys()) {
    if (guardedSymbol && guardedSymbol !== sourceSymbol) continue
    if (!guardedSymbol && !new RegExp(`\\b${sourceSymbol}\\b`).test(text)) continue
    facts.killGuards.push({
      symbol: sourceSymbol,
      accessPath: sourceSymbol,
      riskKind: 'SQL_STRUCTURE',
      sourceLine: lineOf(node),
      evidence: text,
    })
  }
}

function evaluatePythonSink(node: any, rule: any): CtpcDecision {
  if (!enabled()) {
    return { enabled: false, matched: false, action: 'none', reason: 'ctpc disabled' }
  }
  const facts = factsFor(node?.loc?.sourcefile)
  const sqlFacts = globalFactValues('sqlStructureVars')
  let decision: CtpcDecision
  if (facts.killGuards.length > 0) {
    decision = {
      enabled: true,
      matched: true,
      action: 'suppress',
      reason: 'ctpc kill condition matched',
      sourceLine: facts.killGuards[0].sourceLine,
    }
  } else if (sqlFacts.length > 0) {
    decision = {
      enabled: true,
      matched: true,
      action: 'force',
      reason: `ctpc access-path propagation reached SQL structure value ${sqlFacts[0].symbol}`,
      sourceLine: sqlFacts[0].sourceLine,
    }
  } else {
    decision = {
      enabled: true,
      matched: globalFactValues('taintedDictKeys').length > 0 || globalFactValues('taintedSymbols').length > 0,
      action: 'suppress',
      reason: 'ctpc SQL-structure risk not supported by access-path facts',
    }
  }
  appendDiagnostics(decision, node, rule)
  return decision
}

function appendDiagnostics(decision: CtpcDecision, node: any, rule: any): void {
  if (!Config.reportDir) return
  try {
    fs.mkdirSync(Config.reportDir, { recursive: true })
    const facts = factsFor(node?.loc?.sourcefile)
    const diagnostic = {
      file: node?.loc?.sourcefile,
      line: node?.loc?.start?.line,
      sink: rule?.fsig,
      action: decision.action,
      reason: decision.reason,
      facts: {
        taintedSymbols: Array.from(facts.taintedSymbols.values()),
        taintedDictKeys: Array.from(facts.taintedDictKeys.values()),
        preservedDictKeys: Array.from(facts.preservedDictKeys.values()),
        sqlStructureVars: Array.from(facts.sqlStructureVars.values()),
        killGuards: facts.killGuards,
        global: {
          taintedSymbols: globalFactValues('taintedSymbols'),
          taintedDictKeys: globalFactValues('taintedDictKeys'),
          preservedDictKeys: globalFactValues('preservedDictKeys'),
          sqlStructureVars: globalFactValues('sqlStructureVars'),
        },
      },
    }
    fs.appendFileSync(
      path.join(Config.reportDir, 'lapis-ctpc-diagnostics.jsonl'),
      JSON.stringify(diagnostic) + '\n',
      'utf8'
    )
  } catch (error) {
    // Diagnostics must never affect analysis.
  }
}

module.exports = {
  evaluatePythonSink,
  recordAssignment,
  recordBinaryOperation,
  recordIfCondition,
  resetFacts,
}
