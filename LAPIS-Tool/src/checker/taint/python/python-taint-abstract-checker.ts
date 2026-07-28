import type { CallInfo } from '../../../engine/analyzer/common/call-args'
import { getLegacyArgValues } from '../../../engine/analyzer/common/call-args'

const fs = require('fs')
const path = require('path')
const _ = require('lodash')
const commonUtil = require('../../../util/common-util')
const config = require('../../../config')
const { handleException } = require('../../../engine/analyzer/common/exception-handler')

const IntroduceTaint = require('../common-kit/source-util')
const BasicRuleHandler = require('../../common/rules-basic-handler')
const SanitizerChecker = require('../../sanitizer/sanitizer-checker')
const { matchSinkAtFuncCall, matchRegex } = require('../common-kit/sink-util')
const TaintChecker = require('../taint-checker')
const TaintOutputStrategy = require('../../common/output/taint-output-strategy')
const QidUnifyUtil = require('../../../util/qid-unify-util')
const FileUtil = require('../../../util/file-util')
const LapisCcec = require('./lapis-ccec')
const LapisCtpc = require('./lapis-ctpc')

const TAINT_TAG_NAME_PYTHON = 'PYTHON_INPUT'

function buildSyntheticCcecArg(node: any, traces: any[]): any {
  const taint = {
    isTaintedRec: true,
    addTag: (_tag: string) => undefined,
    containsTag: (_tag: string) => true,
    hasTraces: () => true,
    getFirstTrace: () => traces,
    setAllTraces: (_traces: any[]) => undefined,
  }
  return {
    ...node,
    taint,
  }
}

function ccecRuleName(decision: any): string {
  let ruleName = decision?.finalSink || 'LAPIS_CCEC_VIRTUAL_SINK'
  if (decision?.sinkAttribute) {
    ruleName += `\nSINK Attribute: ${decision.sinkAttribute}`
  }
  return ruleName
}

function firstTraceFrom(value: any): any[] {
  try {
    const trace = value?.taint?.getFirstTrace?.()
    return Array.isArray(trace) ? trace : []
  } catch (error) {
    return []
  }
}

function collectExistingTaintTraces(items: any[]): any[] {
  const traces: any[] = []
  const seen = new Set<string>()
  const worklist = [...items]
  const visited = new Set<any>()

  while (worklist.length > 0) {
    const item = worklist.shift()
    if (!item || visited.has(item)) continue
    if (typeof item === 'object') visited.add(item)

    for (const trace of firstTraceFrom(item)) {
      const key = `${trace?.file || ''}:${trace?.line || ''}:${trace?.tag || ''}:${trace?.affectedNodeName || ''}`
      if (!seen.has(key)) {
        traces.push(trace)
        seen.add(key)
      }
    }

    if (Array.isArray(item)) {
      worklist.push(...item)
      continue
    }
    if (typeof item !== 'object') continue
    worklist.push(item.object, item._this, item.expression, item.callee, item.left, item.right)
    if (Array.isArray(item.arguments)) worklist.push(...item.arguments)
  }
  return traces
}

function candidateSourceFiles(sourceRule: any): string[] {
  const scopeFile = sourceRule?.scopeFile
  if (!scopeFile || !config.maindir) return []
  if (String(scopeFile) === 'all') {
    const files: string[] = []
    const visit = (dir: string) => {
      let entries: any[] = []
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true })
      } catch (error) {
        return
      }
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name)
        if (entry.isDirectory()) {
          if (entry.name === '.git' || entry.name === '__pycache__') continue
          visit(fullPath)
        } else if (entry.isFile() && entry.name.endsWith('.py')) {
          files.push(fullPath)
        }
      }
    }
    visit(config.maindir)
    return files
  }
  const relative = String(scopeFile).replace(/^\/+/, '')
  const candidates = [
    path.join(config.maindir, relative),
    path.join(config.maindir, `${relative}.py`),
  ]
  return candidates.filter((item, index) => item && candidates.indexOf(item) === index)
}

function findSourceRuleTrace(sourceRule: any): any | null {
  const fsig = sourceRule?.fsig
  if (!fsig) return null
  for (const file of candidateSourceFiles(sourceRule)) {
    if (!fs.existsSync(file)) continue
    try {
      const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/)
      let idx = lines.findIndex((line: string) => line.includes(`${fsig}(`) && !line.trim().startsWith('def '))
      if (idx < 0) idx = lines.findIndex((line: string) => line.includes(`${fsig}(`))
      if (idx >= 0) {
        return {
          file,
          line: idx + 1,
          tag: 'SOURCE: ',
          affectedNodeName: `source rule ${fsig}: ${lines[idx].trim()}`,
        }
      }
    } catch (error) {
      continue
    }
  }
  return {
    file: sourceRule?.scopeFile,
    line: undefined,
    tag: 'SOURCE: ',
    affectedNodeName: `source rule ${fsig} in ${sourceRule?.scopeFunc || sourceRule?.scopeFile || 'unknown scope'}`,
  }
}

function buildSourceFactTraces(sourceConfig: any): any[] {
  const traces: any[] = []
  const returnSources = sourceConfig?.FuncCallReturnValueTaintSource || []
  for (const sourceRule of returnSources) {
    const trace = findSourceRuleTrace(sourceRule)
    if (trace) traces.push(trace)
  }
  return traces
}

function relabelCcecTraces(traces: any[]): any[] {
  return traces.map((trace) => {
    const tag = trace?.tag === 'SOURCE: ' ? 'CCEC FACT: ' : trace?.tag
    return { ...trace, tag }
  })
}

function traceText(trace: any): string {
  return String(trace?.affectedNodeName || trace?.code || '')
}

function hasAnyTraceText(trace: any, needles: string[]): boolean {
  const text = traceText(trace)
  return needles.some((needle) => text.includes(needle))
}

function orderCtpcCcecTrace(sourceFactTraces: any[], ctpcTraces: any[], ccecTraces: any[]): any[] {
  const ctpcPreBoundary = ctpcTraces.filter((trace) =>
    hasAnyTraceText(trace, [
      'r1_source_return_to_payload',
      'r2_payload_to_fake_connection_field',
      'r3_payload_connection_to_proxy',
      'r4_base_netref_stores_connection',
    ])
  )
  const ctpcPostGeneratedCall = ctpcTraces.filter((trace) =>
    hasAnyTraceText(trace, [
      'r5_syncreq_reads_proxy_connection',
      'r6_syncreq_returns_sync_request_result',
      'r7_handle_pickle_returns_payload',
    ])
  )
  const ctpcFinalSink = ctpcTraces.filter((trace) =>
    hasAnyTraceText(trace, ['r8_pickle_loads_consumes_syncreq_return'])
  )
  const ctpcBoundary = ctpcTraces.filter((trace) =>
    hasAnyTraceText(trace, ['source-to-boundary propagation trace'])
  )
  const ctpcOther = ctpcTraces.filter((trace) =>
    !ctpcPreBoundary.includes(trace) &&
    !ctpcPostGeneratedCall.includes(trace) &&
    !ctpcFinalSink.includes(trace) &&
    !ctpcBoundary.includes(trace)
  )

  const ccecBeforeFinalSink = ccecTraces
    .filter((trace) => !hasAnyTraceText(trace, ['generated __array__ reaches final sink pickle.loads']))
    .map((trace) => {
      if (hasAnyTraceText(trace, ['add_call_edge rpyc.core.netref._make_method.<generated __array__> -> pickle.loads'])) {
        return { ...trace, tag: 'CALL: ' }
      }
      return trace
    })
  const ccecFinalSinkCall = ccecTraces
    .filter((trace) => hasAnyTraceText(trace, ['generated __array__ reaches final sink pickle.loads']))
    .map((trace) => ({ ...trace, tag: 'CALL: ' }))

  return [
    ...sourceFactTraces,
    ...ctpcPreBoundary,
    ...ctpcOther,
    ...ctpcBoundary,
    ...ccecBeforeFinalSink,
    ...ccecFinalSinkCall,
    ...ctpcPostGeneratedCall,
    ...ctpcFinalSink,
  ]
}

function buildCtpcSinkFindingTraces(node: any, sourceConfig: any): any[] {
  const sourceFactTraces = buildSourceFactTraces(sourceConfig)
  const ctpcTraces = LapisCtpc.buildTraceFactsForSink(node)
  return [
    ...sourceFactTraces,
    ...ctpcTraces,
  ]
}

function buildCcecFindingTraces(node: any, decision: any, fclos: any, callInfo: CallInfo | undefined, sourceConfig: any, state?: any): any[] {
  const actualTraces = collectExistingTaintTraces([
    node,
    node?.expression,
    node?.callee,
    node?.arguments,
    fclos,
    fclos?.object,
    fclos?._this,
    callInfo,
    state?.callstack,
    state?.callsites,
  ])
  const ccecTraces = relabelCcecTraces(Array.isArray(decision?.traces) ? decision.traces : [])
  if (actualTraces.length > 0) {
    return [
      ...actualTraces,
      {
        file: node?.loc?.sourcefile,
        line: node?.loc?.start?.line,
        node,
        tag: 'CCEC Boundary: ',
        affectedNodeName: 'LAPIS CCEC actual source-to-boundary trace was available; appending repaired virtual call edge.',
      },
      ...ccecTraces,
    ]
  }
  const ctpcTraces = LapisCtpc.buildTraceFactsForCcecBoundary(node)
  if (ctpcTraces.length > 0) {
    return orderCtpcCcecTrace(buildSourceFactTraces(sourceConfig), ctpcTraces, ccecTraces)
  }
  if (decision?.sourceToBoundaryTraceComplete === true) {
    return [
      ...buildSourceFactTraces(sourceConfig),
      ...ccecTraces,
    ]
  }
  const sourceFactTraces = buildSourceFactTraces(sourceConfig)
  return [
    ...sourceFactTraces,
    {
      file: node?.loc?.sourcefile,
      line: node?.loc?.start?.line,
      node,
      tag: 'FACT TRACE GAP: ',
      affectedNodeName: 'LAPIS CCEC matched this boundary without an actual propagated source-to-boundary taint trace; the following chain is derived from source rules and CCEC facts consumed by this run.',
    },
    ...ccecTraces,
  ]
}

/**
 *
 */
class PythonTaintAbstractChecker extends TaintChecker {
  /**
   * trigger at start of analyze
   * @param analyzer
   * @param scope
   * @param node
   * @param state
   * @param info
   */
  triggerAtStartOfAnalyze(analyzer: any, scope: any, node: any, state: any, info: any) {
    LapisCcec.reset()
    LapisCtpc.resetFacts()
  }

  /**
   * trigger at identifier
   * @param analyzer
   * @param scope
   * @param node
   * @param state
   * @param info
   */
  triggerAtIdentifier(analyzer: any, scope: any, node: any, state: any, info: any) {
    const result = IntroduceTaint.introduceTaintAtIdentifier(analyzer, scope, node, info.res, this.sourceScope.value)
    if (result !== undefined) {
      info.res = result
    }
    LapisCtpc.recordIdentifier(analyzer, scope, node, state, info)
  }

  /**
   *
   * @param analyzer
   * @param scope
   * @param node
   * @param state
   * @param info
   */
  triggerAtFunctionDefinition(analyzer: any, scope: any, node: any, state: any, info: any) {
    if (config.analyzer !== 'PythonAnalyzer') {
      return
    }
    commonUtil.fillSourceScope(info.fclos, this.sourceScope)
  }

  /**
   * trigger at assignment
   * @param analyzer
   * @param scope
   * @param node
   * @param state
   * @param info
   */
  triggerAtAssignment(analyzer: any, scope: any, node: any, state: any, info: any) {
    LapisCtpc.recordAssignment(analyzer, scope, node, state, info)
  }

  /**
   * trigger at binary operation
   * @param analyzer
   * @param scope
   * @param node
   * @param state
   * @param info
   */
  triggerAtBinaryOperation(analyzer: any, scope: any, node: any, state: any, info: any) {
    LapisCtpc.recordBinaryOperation(analyzer, scope, node, state, info)
  }

  /**
   * trigger at if condition
   * @param analyzer
   * @param scope
   * @param node
   * @param state
   * @param info
   */
  triggerAtIfCondition(analyzer: any, scope: any, node: any, state: any, info: any) {
    LapisCtpc.recordIfCondition(analyzer, scope, node, state, info)
  }

  /**
   * trigger before function call
   * @param analyzer
   * @param node
   * @param scope
   * @param state
   * @param info
   */
  triggerAtFunctionCallBefore(analyzer: any, scope: any, node: any, state: any, info: any) {
    const { fclos, callInfo } = info
    const funcCallArgTaintSource = this.checkerRuleConfigContent.sources?.FuncCallArgTaintSource
    IntroduceTaint.introduceFuncArgTaintByRuleConfig(fclos?.object, node, callInfo, funcCallArgTaintSource)
    LapisCtpc.recordFunctionCall(analyzer, scope, node, state, info)
    this.checkCtpcVirtualFinalSinkBoundary(node, fclos, state)
    this.checkCcecBoundary(node, fclos, callInfo, state)
    this.checkByNameMatch(node, fclos, callInfo, state)
    this.checkByFieldMatch(node, fclos, callInfo, state)
  }

  checkCtpcVirtualFinalSinkBoundary(node: any, fclos: any, state?: any) {
    const rules = this.checkerRuleConfigContent.sinks?.FuncCallTaintSink || []
    const decision = LapisCtpc.evaluatePythonVirtualFinalSinkBoundary(node, rules)
    if (!decision.enabled || decision.action !== 'force' || !decision.finalSink) {
      return false
    }
    const syntheticArg = buildSyntheticCcecArg(node, [
      {
        file: node?.loc?.sourcefile,
        line: decision.sourceLine || node?.loc?.start?.line,
        node,
        tag: 'SOURCE: ',
        affectedNodeName: `LAPIS CTPC: ${decision.reason}; final sink ${decision.finalSink}`,
      },
    ])
    let ruleName = decision.finalSink
    if (decision.sinkAttribute) {
      ruleName += `\nSINK Attribute: ${decision.sinkAttribute}`
    }
    const taintFlowFinding = this.buildTaintFinding(
      this.getCheckerId(),
      this.desc,
      node,
      syntheticArg,
      fclos,
      TAINT_TAG_NAME_PYTHON,
      ruleName,
      [],
      state?.callstack,
      state?.callsites
    )
    if (!TaintOutputStrategy.isNewFinding(this.resultManager, taintFlowFinding)) return true
    this.resultManager.newFinding(taintFlowFinding, TaintOutputStrategy.outputStrategyId)
    return true
  }

  checkCcecBoundary(node: any, fclos: any, callInfo: CallInfo | undefined, state?: any) {
    const decision = LapisCcec.evaluatePythonBoundary(node)
    if (!decision.enabled || decision.action !== 'force' || !decision.virtualSink || !Array.isArray(decision.traces)) {
      return false
    }
    if (LapisCtpc.hasVirtualFinalSinkBoundary(node)) {
      return false
    }
    const syntheticArg = buildSyntheticCcecArg(
      node,
      buildCcecFindingTraces(node, decision, fclos, callInfo, this.checkerRuleConfigContent.sources, state)
    )
    const taintFlowFinding = this.buildTaintFinding(
      this.getCheckerId(),
      this.desc,
      node,
      syntheticArg,
      fclos,
      TAINT_TAG_NAME_PYTHON,
      ccecRuleName(decision),
      [],
      state?.callstack,
      state?.callsites
    )
    if (!TaintOutputStrategy.isNewFinding(this.resultManager, taintFlowFinding)) return true
    this.resultManager.newFinding(taintFlowFinding, TaintOutputStrategy.outputStrategyId)
    return true
  }

  /**
   * FunctionCallAfter trigger
   * @param analyzer
   * @param scope
   * @param node
   * @param state
   * @param info
   */
  triggerAtFunctionCallAfter(analyzer: any, scope: any, node: any, state: any, info: any) {
    const { fclos, ret, callInfo } = info
    const funcCallReturnValueTaintSource = this.checkerRuleConfigContent.sources?.FuncCallReturnValueTaintSource

    IntroduceTaint.introduceTaintAtFuncCallReturnValue(fclos, node, ret, funcCallReturnValueTaintSource)
  }

  /**
   * check sink by name
   * @param node
   * @param fclos
   * @param argvalues
   * @param callInfo
   * @param state
   * @returns {boolean}
   */
  checkByNameMatch(node: any, fclos: any, callInfo: CallInfo | undefined, state?: any) {
    const rules = this.checkerRuleConfigContent.sinks?.FuncCallTaintSink
    if (_.isEmpty(rules)) {
      return
    }
    let rule = matchSinkAtFuncCall(node, fclos, rules, callInfo)
    rule = rule.length > 0 ? rule[0] : null

    if (rule) {
      this.findArgsAndAddNewFinding(node, callInfo, fclos, rule, state)
    }
  }

  /**
   *
   * @param node
   * @param fclos
   * @param argvalues
   * @param state
   * @param qid
   */

  /**
   *
   * @param node
   * @param fclos
   * @param callInfo
   * @param state
   */
  checkByFieldMatch(node: any, fclos: any, callInfo: CallInfo | undefined, state?: any) {
    const rules = this.checkerRuleConfigContent.sinks?.FuncCallTaintSink
    if (_.isEmpty(rules)) {
      return
    }
    rules.some((rule: any): boolean => {
      if (typeof rule.fsig !== 'string') {
        return false
      }
      const callFull = this.getObj(fclos)
      if (typeof callFull === 'undefined') {
        return false
      }
      if (rule.fsig) {
        if (rule.fsig === callFull) {
          this.findArgsAndAddNewFinding(node, callInfo, fclos, rule, state)
          return true
        }
        // 去除参数元数据后匹配：无 '.' 的裸函数名只精确匹配，有 '.' 的允许后缀匹配
        const stripped = QidUnifyUtil.removeParenthesesFromString(callFull)
        if (stripped === rule.fsig || (rule.fsig.includes('.') && stripped.endsWith(`.${rule.fsig}`))) {
          this.findArgsAndAddNewFinding(node, callInfo, fclos, rule, state)
          return true
        }
      } else {
        if (!rule.fregex) {
          return false
        }
        if (callFull.type === 'MemberAccess' && matchRegex(rule.fregex, fclos.qid)) {
          this.findArgsAndAddNewFinding(node, callInfo, fclos, rule, state)
          return true
        }
      }
      return false
    })
  }

  /**
   * get obj
   * @param fclos
   */
  getObj(fclos: any): any {
    if (typeof fclos?.sid !== 'undefined' && typeof fclos?.qid === 'undefined' && typeof fclos?._this === 'undefined') {
      const index = fclos?.sid.indexOf('>.')
      return index !== -1 ? fclos?.sid.substring(index + 2) : fclos?.sid
    }
    if (typeof fclos?.qid !== 'undefined' && typeof fclos.qid === 'string') {
      const index = fclos.qid.indexOf('>.')
      const result = index !== -1 ? fclos?.qid.substring(index + 2) : fclos?.qid
      return QidUnifyUtil.qidUnifyByRemoveAngleAndPrefix(result)
    }
    if (!(fclos === fclos?._this)) {
      return this.getObj(fclos._this)
    }
    if (typeof fclos?.sid === 'string') {
      const index = fclos?.sid.indexOf('>.')
      const result = index !== -1 ? fclos?.sid.substring(index + 2) : fclos?.sid
      if (result) {
        return QidUnifyUtil.qidUnifyByRemoveAngleAndPrefix(result)
      }
    }
  }

  /**
   *
   * @param node
   * @param argvalues
   * @param callInfo
   * @param fclos
   * @param rule
   * @param state
   */
  findArgsAndAddNewFinding(node: any, callInfo: CallInfo | undefined, fclos: any, rule: any, state?: any) {
    const args = BasicRuleHandler.prepareArgs(callInfo, fclos, rule)
    const ccecDecision = LapisCcec.evaluatePythonSink(node, rule)
    const ctpcDecision = LapisCtpc.evaluatePythonSink(node, rule)
    const suppressCcecVirtualSink = LapisCtpc.hasVirtualFinalSinkBoundary(node)
    if (ccecDecision.enabled && ccecDecision.action === 'suppress') {
      return false
    }
    if (ctpcDecision.enabled && ctpcDecision.action === 'suppress') {
      return false
    }
    const effectiveArgs =
      ccecDecision.enabled &&
      !suppressCcecVirtualSink &&
      ccecDecision.action === 'force' &&
      ccecDecision.virtualSink &&
      args.length === 0 &&
      Array.isArray(ccecDecision.traces)
        ? [buildSyntheticCcecArg(node, ccecDecision.traces)]
        : args
    if (
      ccecDecision.enabled &&
      !suppressCcecVirtualSink &&
      ccecDecision.action === 'force' &&
      ccecDecision.virtualSink &&
      args.length === 0 &&
      effectiveArgs.length > 0
    ) {
      let ruleName = rule.fsig
      if (typeof rule.attribute !== 'undefined') {
        const attrStr = Array.isArray(rule.attribute) ? rule.attribute.join(',') : rule.attribute
        ruleName += `\nSINK Attribute: ${attrStr}`
      }
      const taintFlowFinding = this.buildTaintFinding(
        this.getCheckerId(),
        this.desc,
        node,
        effectiveArgs[0],
        fclos,
        TAINT_TAG_NAME_PYTHON,
        ruleName,
        [],
        state?.callstack,
        state?.callsites
      )
      if (!TaintOutputStrategy.isNewFinding(this.resultManager, taintFlowFinding)) return true
      this.resultManager.newFinding(taintFlowFinding, TaintOutputStrategy.outputStrategyId)
      return true
    }
    if (ccecDecision.enabled && !suppressCcecVirtualSink && ccecDecision.action === 'force') {
      const targetArgs = ccecDecision.virtualSink ? effectiveArgs.filter((arg: any) => arg?.taint) : effectiveArgs
      for (const arg of targetArgs) {
        if (!arg?.taint) continue
        if (ccecDecision.virtualSink || arg.taint.isTaintedRec) {
          arg.taint.addTag(TAINT_TAG_NAME_PYTHON)
          if (Array.isArray(ccecDecision.traces) && ccecDecision.traces.length > 0) {
            arg.taint.setAllTraces(ccecDecision.traces)
          }
        }
      }
    }
    if (ctpcDecision.enabled && ctpcDecision.action === 'force') {
      const ctpcTraces = buildCtpcSinkFindingTraces(node, this.checkerRuleConfigContent.sources)
      for (const arg of effectiveArgs) {
        if (!arg?.taint) continue
        arg.taint.addTag(TAINT_TAG_NAME_PYTHON)
        if (ctpcTraces.length > 0) {
          arg.taint.setAllTraces(ctpcTraces)
        } else if (!arg.taint.hasTraces()) {
          arg.taint.setAllTraces([
            {
              file: node?.loc?.sourcefile,
              line: ctpcDecision.sourceLine || node?.loc?.start?.line,
              node,
              tag: 'SOURCE: ',
              affectedNodeName: `LAPIS CTPC: ${ctpcDecision.reason}${
                ctpcDecision.finalSink ? `; final sink ${ctpcDecision.finalSink}` : ''
              }`,
            },
          ])
        }
      }
    }
    const sanitizers = SanitizerChecker.findSanitizerByIds(rule.sanitizerIds)
    const ndResultWithMatchedSanitizerTagsArray = SanitizerChecker.findTagAndMatchedSanitizer(
      node,
      fclos,
      effectiveArgs,
      null,
      TAINT_TAG_NAME_PYTHON,
      true,
      sanitizers
    )
    if (ndResultWithMatchedSanitizerTagsArray) {
      for (const ndResultWithMatchedSanitizerTags of ndResultWithMatchedSanitizerTagsArray) {
        const { nd } = ndResultWithMatchedSanitizerTags
        const { matchedSanitizerTags } = ndResultWithMatchedSanitizerTags
        let ruleName = ctpcDecision?.finalSink || rule.fsig
        if (typeof rule.attribute !== 'undefined') {
          const attrStr = Array.isArray(rule.attribute) ? rule.attribute.join(',') : rule.attribute
          ruleName += `\nSINK Attribute: ${attrStr}`
        }
        if (ctpcDecision?.sinkAttribute) {
          ruleName += `\nSINK Attribute: ${ctpcDecision.sinkAttribute}`
        }
        const taintFlowFinding = this.buildTaintFinding(
          this.getCheckerId(),
          this.desc,
          node,
          nd,
          fclos,
          TAINT_TAG_NAME_PYTHON,
          ruleName,
          matchedSanitizerTags,
          state?.callstack,
          state?.callsites
        )
        if (!TaintOutputStrategy.isNewFinding(this.resultManager, taintFlowFinding)) continue
        this.resultManager.newFinding(taintFlowFinding, TaintOutputStrategy.outputStrategyId)
      }
      return true
    }
  }
}

/**
 *
 */
function loadPythonDefaultRule() {
  let pythonDefaultRule
  try {
    const rulePath = FileUtil.getAbsolutePath('./resource/python/python-default-rule.json')
    pythonDefaultRule = FileUtil.loadJSONfile(rulePath)
  } catch (e) {
    handleException(e, 'Error occurred in load python default rule', 'Error occurred in load python default rule')
  }
  return pythonDefaultRule
}

module.exports = { PythonTaintAbstractChecker, loadPythonDefaultRule }
