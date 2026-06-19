import type { CallInfo } from '../../../engine/analyzer/common/call-args'
import { getLegacyArgValues } from '../../../engine/analyzer/common/call-args'

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
    this.checkCcecBoundary(node, fclos, state)
    this.checkByNameMatch(node, fclos, callInfo, state)
    this.checkByFieldMatch(node, fclos, callInfo, state)
  }

  checkCcecBoundary(node: any, fclos: any, state?: any) {
    const decision = LapisCcec.evaluatePythonBoundary(node)
    if (!decision.enabled || decision.action !== 'force' || !decision.virtualSink || !Array.isArray(decision.traces)) {
      return false
    }
    const syntheticArg = buildSyntheticCcecArg(node, decision.traces)
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
    if (ccecDecision.enabled && ccecDecision.action === 'suppress') {
      return false
    }
    if (ctpcDecision.enabled && ctpcDecision.action === 'suppress') {
      return false
    }
    const effectiveArgs =
      ccecDecision.enabled &&
      ccecDecision.action === 'force' &&
      ccecDecision.virtualSink &&
      args.length === 0 &&
      Array.isArray(ccecDecision.traces)
        ? [buildSyntheticCcecArg(node, ccecDecision.traces)]
        : args
    if (
      ccecDecision.enabled &&
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
    if (ccecDecision.enabled && ccecDecision.action === 'force') {
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
      for (const arg of effectiveArgs) {
        if (!arg?.taint) continue
        arg.taint.addTag(TAINT_TAG_NAME_PYTHON)
        if (!arg.taint.hasTraces()) {
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
