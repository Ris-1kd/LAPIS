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
  finalSink?: string
  sinkAttribute?: string
}

type AccessPathFact = {
  fact?: string
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
  genericFacts: Map<string, AccessPathFact>
  killGuards: AccessPathFact[]
  scannedGuardLines: Set<number>
}

type FactMapName = 'taintedSymbols' | 'taintedDictKeys' | 'preservedDictKeys' | 'sqlStructureVars' | 'genericFacts'

let cachedPath = ''
let cachedCtpc: any = null
const fileFacts = new Map<string, FileFacts>()

function emptyFacts(): FileFacts {
  return {
    taintedSymbols: new Map(),
    taintedDictKeys: new Map(),
    preservedDictKeys: new Map(),
    sqlStructureVars: new Map(),
    genericFacts: new Map(),
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

function allFacts(localFacts: FileFacts): AccessPathFact[] {
  const result: AccessPathFact[] = []
  for (const scope of allFactScopes(localFacts)) {
    result.push(...scope.taintedSymbols.values())
    result.push(...scope.taintedDictKeys.values())
    result.push(...scope.preservedDictKeys.values())
    result.push(...scope.sqlStructureVars.values())
    result.push(...scope.genericFacts.values())
  }
  return result
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
  if (!ctpc) return []
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
  if (!Array.isArray(edges)) return []
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

function addGenericFact(facts: FileFacts, key: string, fact: AccessPathFact): void {
  const normalized = key.replace(/^\$/, '')
  addFact(facts.genericFacts, normalized, { ...fact, symbol: normalized })
}

function factMapName(factName: string | undefined): FactMapName | undefined {
  if (factName === 'tainted_symbol') return 'taintedSymbols'
  if (factName === 'mapping_key') return 'taintedDictKeys'
  if (factName === 'sql_structure_value') return 'sqlStructureVars'
  if (factName) return 'genericFacts'
  return undefined
}

function ruleFactName(ruleSide: any, fallback: string): string {
  return String(ruleSide?.fact || fallback)
}

function ruleRiskKind(rule: any): string {
  return rule?.to?.risk_kind || rule?.risk_kind || riskKind('GENERIC_RISK')
}

function factKeyFromRule(ruleSide: any, fallback: string): string {
  const expr = String(ruleSide?.expr || ruleSide?.access_path || fallback)
  const cleaned = expr
    .replace(/\$return/g, fallback)
    .replace(/\$lhs/g, fallback)
    .replace(/\$result/g, fallback)
    .replace(/\$path/g, fallback)
    .replace(/^\$/, '')
  return cleaned || fallback
}

function textContainsSymbol(text: string, symbol: string | undefined): boolean {
  if (!text || !symbol) return false
  const escaped = symbol.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(`(^|[^A-Za-z0-9_])${escaped}([^A-Za-z0-9_]|$)`).test(text)
}

function factMatchesText(fact: AccessPathFact, text: string): boolean {
  if (!text) return false
  if (textContainsSymbol(text, fact.symbol)) return true
  if (fact.accessPath && text.includes(fact.accessPath)) return true
  const base = fact.accessPath?.split(/[.[(]/)[0]
  if (base && textContainsSymbol(text, base)) return true
  const leaf = fact.accessPath?.split(/[.[(]/).filter(Boolean).pop()
  return !!leaf && textContainsSymbol(text, leaf)
}

function sourceFactForExpression(facts: FileFacts, text: string): AccessPathFact | undefined {
  return allFacts(facts).find((fact) => factMatchesText(fact, text))
}

function genericPropagationRules(event: string): any[] {
  const ctpc = loadCtpc()
  if (ctpc?.schema_version !== 'ctpc.v2') return []
  const edges = Array.isArray(ctpc.propagation_edges) ? ctpc.propagation_edges : []
  const summaries = Array.isArray(ctpc.function_summaries) ? ctpc.function_summaries : []
  const upgrades = Array.isArray(ctpc.risk_upgrades) ? ctpc.risk_upgrades : []
  return [...edges, ...summaries, ...upgrades].filter((rule: any) => rule.event === event)
}

function rulesForCurrentSink(node: any, sinkRule: any): any[] {
  const callText = pretty(node)
  const call = callExpressionParts(callText)
  const actual = call?.callee || sinkRule?.fsig || ''
  return genericPropagationRules('sink').filter((rule: any) => {
    const callee = rule.pattern?.callee
    if (!callee) return true
    return calleeMatches(actual, callee) || calleeMatches(String(sinkRule?.fsig || ''), callee)
  })
}

function hasVirtualFinalSinkBoundary(node: any): boolean {
  if (!enabled()) return false
  const callText = pretty(node)
  const call = callExpressionParts(callText)
  const actual = call?.callee || ''
  return genericPropagationRules('sink').some((rule: any) => {
    const virtualFinalSink = rule.pattern?.virtual_final_sink
    const callee = rule.pattern?.callee
    return !!virtualFinalSink && evidenceMatchesNode(rule, node) && (!callee || calleeMatches(actual, callee))
  })
}

function evidenceMatchesNode(rule: any, node: any): boolean {
  const evidenceFile = rule?.evidence?.file
  if (!evidenceFile) return true
  const sourceFile = String(node?.loc?.sourcefile || '')
  const normalizedEvidence = String(evidenceFile).replace(/\\/g, '/')
  const normalizedSource = sourceFile.replace(/\\/g, '/')
  if (!normalizedSource.endsWith(normalizedEvidence)) return false
  const evidenceLine = Number(rule?.evidence?.line)
  return !Number.isFinite(evidenceLine) || evidenceLine === node?.loc?.start?.line
}

function evaluatePythonVirtualFinalSinkBoundary(node: any, configuredSinkRules: any[]): CtpcDecision {
  if (!enabled()) {
    return { enabled: false, matched: false, action: 'none', reason: 'ctpc disabled' }
  }
  const facts = factsFor(node?.loc?.sourcefile)
  const callText = pretty(node)
  const call = callExpressionParts(callText)
  if (!call) {
    return { enabled: true, matched: false, action: 'none', reason: 'not a call expression' }
  }
  const virtualBoundaryRule = genericPropagationRules('sink').find((rule: any) => {
    const virtualFinalSink = rule.pattern?.virtual_final_sink
    const callee = rule.pattern?.callee
    return !!virtualFinalSink && evidenceMatchesNode(rule, node) && (!callee || calleeMatches(call.callee, callee))
  })
  if (!virtualBoundaryRule) {
    return { enabled: true, matched: false, action: 'none', reason: 'no ctpc virtual final sink boundary' }
  }
  const finalSink = String(virtualBoundaryRule.pattern?.virtual_final_sink || '')
  const configuredFinalSink = (configuredSinkRules || []).find((rule: any) => calleeMatches(finalSink, rule?.fsig))
  if (!configuredFinalSink) {
    const decision = {
      enabled: true,
      matched: true,
      action: 'suppress' as const,
      reason: `ctpc virtual final sink ${finalSink} is not present in configured sink rules`,
    }
    appendDiagnostics(decision, node, { fsig: finalSink || '<virtual-final-sink>' })
    return decision
  }
  const sqlFacts = globalFactValues('sqlStructureVars')
  const genericRiskFacts = globalFactValues('genericFacts').filter((fact) => !!fact.riskKind)
  const riskFacts = [...sqlFacts, ...genericRiskFacts]
  let decision: CtpcDecision
  if (facts.killGuards.length > 0) {
    decision = {
      enabled: true,
      matched: true,
      action: 'suppress',
      reason: 'ctpc kill condition matched',
      sourceLine: facts.killGuards[0].sourceLine,
    }
  } else if (riskFacts.length > 0) {
    const fact = riskFacts[0]
    decision = {
      enabled: true,
      matched: true,
      action: 'force',
      reason: `ctpc access-path propagation reached ${fact.riskKind || 'risk'} value ${fact.symbol}`,
      sourceLine: fact.sourceLine,
      finalSink,
      sinkAttribute: `LAPIS CTPC virtual sink: ${finalSink}`,
    }
  } else {
    decision = {
      enabled: true,
      matched: true,
      action: 'suppress',
      reason: 'ctpc virtual final sink boundary has no validated access-path facts',
    }
  }
  appendDiagnostics(decision, node, configuredFinalSink)
  return decision
}

function callExpressionParts(callText: string): { callee: string; args: string[] } | undefined {
  const match = callText.match(/([A-Za-z_][A-Za-z0-9_.]*)\s*\((.*)\)\s*$/)
  if (!match) return undefined
  return {
    callee: match[1],
    args: match[2].split(',').map((arg) => arg.trim()).filter((arg) => arg.length > 0),
  }
}

function callArgsByName(callText: string): Record<string, string> {
  const parts = callExpressionParts(callText)
  const result: Record<string, string> = {}
  if (!parts) return result
  for (const arg of parts.args) {
    const match = arg.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/)
    if (match) result[match[1]] = match[2]
  }
  return result
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
  recordGenericAssignment(facts, target, rightText, node, evidence, info)
  recordDictLiteralKey(facts, target, rightText, node, evidence)
  recordDictComprehensionKeyPreserved(facts, target, rightText, node, evidence)
  recordPercentFormatResult(facts, target, info?.rvalue, rightText, node, evidence)
}

function recordIdentifier(analyzer: any, scope: any, node: any, state: any, info: any): void {
  if (!enabled()) return
  const name = symbolName(node)
  if (!name || !isTainted(info?.res)) return
  const facts = factsFor(node?.loc?.sourcefile)
  const evidence = pretty(node) || name
  const fact = {
    fact: 'tainted_symbol',
    symbol: name,
    accessPath: name,
    riskKind: riskKind(),
    sourceLine: lineOf(node),
    evidence,
  }
  addFact(facts.taintedSymbols, name, fact)
  addGenericFact(facts, name, fact)
}

function recordGenericAssignment(
  facts: FileFacts,
  target: string,
  rightText: string,
  node: any,
  evidence: string,
  info: any
): void {
  for (const rule of genericPropagationRules('assignment')) {
    const kind = rule.pattern?.kind || ''
    const sourceFact = sourceFactForExpression(facts, rightText) ||
      (isTainted(info?.rvalue)
        ? {
            fact: ruleFactName(rule.from, 'tainted_symbol'),
            symbol: target,
            accessPath: target,
            riskKind: ruleRiskKind(rule),
            sourceLine: lineOf(node),
            evidence,
          }
        : undefined)
    if (!sourceFact) continue

    const supported =
      kind === 'direct_assignment' ||
      kind === 'tuple_list_element' ||
      kind === 'constructor_keyword_capture' ||
      (kind === 'generator_tuple_index_join' && /\.join\s*\(/.test(rightText)) ||
      (kind === 'fstring_sql_interpolation' && /(^|[^A-Za-z])f["']/.test(rightText)) ||
      (kind === 'path_join_keep_filename' && /(?:os\.path\.)?join\s*\(/.test(rightText)) ||
      (kind === 'filesystem_path_assignment' && /path/i.test(target))
    if (!supported) continue

    const factName = ruleFactName(rule.to, ruleFactName(rule.from, 'generic_fact'))
    const key = factKeyFromRule(rule.to, target)
    const propagated: AccessPathFact = {
      fact: factName,
      symbol: key,
      accessPath: rule.to?.access_path || key,
      riskKind: ruleRiskKind(rule) || sourceFact.riskKind,
      sourceLine: sourceFact.sourceLine || lineOf(node),
      evidence,
    }
    addGenericFact(facts, key, propagated)
    if (propagated.riskKind) {
      addFact(facts.sqlStructureVars, key, propagated)
    }
  }
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

function recordFunctionCall(analyzer: any, scope: any, node: any, state: any, info: any): void {
  if (!enabled()) return
  const file = node?.loc?.sourcefile
  const facts = factsFor(file)
  const callText = pretty(node)
  const call = callExpressionParts(callText)
  if (!call) return
  const namedArgs = callArgsByName(callText)

  for (const rule of genericPropagationRules('function_call')) {
    const kind = rule.pattern?.kind || ''
    const callee = rule.pattern?.callee
    if (callee && !calleeMatches(call.callee, callee)) continue

    let sourceText = ''
    if (Number.isInteger(rule.pattern?.argument_index)) {
      sourceText = call.args[rule.pattern.argument_index] || ''
    } else if (rule.pattern?.keyword) {
      sourceText = namedArgs[rule.pattern.keyword] || ''
    } else if (kind === 'constructor_keyword_capture') {
      sourceText = namedArgs.file_name || namedArgs.filename || ''
    } else {
      sourceText = call.args.join(', ')
    }
    const sourceFact = sourceFactForExpression(facts, sourceText)
    if (!sourceFact) continue

    const factName = ruleFactName(rule.to, ruleFactName(rule.from, 'generic_fact'))
    const key = factKeyFromRule(rule.to, sourceText || call.callee)
    const propagated: AccessPathFact = {
      fact: factName,
      symbol: key,
      accessPath: rule.to?.access_path || key,
      riskKind: ruleRiskKind(rule) || sourceFact.riskKind,
      sourceLine: sourceFact.sourceLine || lineOf(node),
      evidence: callText,
    }
    addGenericFact(facts, key, propagated)
    if (propagated.riskKind) {
      addFact(facts.sqlStructureVars, key, propagated)
    }
  }

  for (const rule of genericPropagationRules('sink')) {
    const kind = rule.pattern?.kind || ''
    const callee = rule.pattern?.callee
    if (callee && !calleeMatches(call.callee, callee)) continue
    if (kind !== 'filesystem_sink_argument' && kind !== 'sql_sink_argument' && kind !== 'sink_argument') continue
    const argIndex = Number.isInteger(rule.pattern?.argument_index) ? rule.pattern.argument_index : 0
    const argText = call.args[argIndex] || call.args.join(', ')
    const sourceFact = sourceFactForExpression(facts, argText)
    if (!sourceFact) continue
    const key = factKeyFromRule(rule.to, argText || call.callee)
    const riskFact: AccessPathFact = {
      fact: ruleFactName(rule.to, 'sink_reached_value'),
      symbol: key,
      accessPath: rule.to?.access_path || key,
      riskKind: ruleRiskKind(rule) || sourceFact.riskKind,
      sourceLine: sourceFact.sourceLine || lineOf(node),
      evidence: callText,
    }
    addGenericFact(facts, key, riskFact)
    addFact(facts.sqlStructureVars, key, riskFact)
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
  const genericRiskFacts = globalFactValues('genericFacts').filter((fact) => !!fact.riskKind)
  const riskFacts = [...sqlFacts, ...genericRiskFacts]
  const currentSinkRules = rulesForCurrentSink(node, rule)
  const virtualBoundaryRule = currentSinkRules.find((item: any) => item.pattern?.virtual_final_sink)
  const call = callExpressionParts(pretty(node))
  const argIndex = Number(rule?.args?.[0] || 0)
  const sinkArgText = call?.args?.[argIndex] || call?.args?.[0] || ''
  const sinkArgRiskFact = sourceFactForExpression(facts, sinkArgText)
  let decision: CtpcDecision
  if (facts.killGuards.length > 0) {
    decision = {
      enabled: true,
      matched: true,
      action: 'suppress',
      reason: 'ctpc kill condition matched',
      sourceLine: facts.killGuards[0].sourceLine,
    }
  } else if (sinkArgRiskFact || (virtualBoundaryRule && riskFacts.length > 0)) {
    const fact = sinkArgRiskFact || riskFacts[0]
    const finalSink = currentSinkRules.find((item: any) => item.pattern?.virtual_final_sink)?.pattern?.virtual_final_sink
      || currentSinkRules.find((item: any) => item.to?.expr)?.to?.expr
      || rule?.fsig
    decision = {
      enabled: true,
      matched: true,
      action: 'force',
      reason: `ctpc access-path propagation reached ${fact.riskKind || 'risk'} value ${fact.symbol}`,
      sourceLine: fact.sourceLine,
      finalSink,
      sinkAttribute: finalSink && finalSink !== rule?.fsig ? `LAPIS CTPC virtual sink: ${finalSink}` : undefined,
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
        genericFacts: Array.from(facts.genericFacts.values()),
        killGuards: facts.killGuards,
        global: {
          taintedSymbols: globalFactValues('taintedSymbols'),
          taintedDictKeys: globalFactValues('taintedDictKeys'),
          preservedDictKeys: globalFactValues('preservedDictKeys'),
          sqlStructureVars: globalFactValues('sqlStructureVars'),
          genericFacts: globalFactValues('genericFacts'),
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
  evaluatePythonVirtualFinalSinkBoundary,
  hasVirtualFinalSinkBoundary,
  recordAssignment,
  recordBinaryOperation,
  recordFunctionCall,
  recordIdentifier,
  recordIfCondition,
  resetFacts,
}
