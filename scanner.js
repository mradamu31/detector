import { scanContent } from './detector.js';
import { llmScan } from './llm-scanner.js';

/**
 * fullScan — pattern scan + optional LLM escalation for medium-confidence results.
 * @param {string} content
 * @param {object} [opts] — { llmScanConfig?: { enabled, provider, endpoint, model, apiKeyEnv, timeoutMs } }
 * @returns {Promise<{risk, flags, message, llmResult?}>}
 */
export async function fullScan(content, opts = {}) {
  if (!content) return { risk: 'none', flags: [], message: null };

  const patternResult = scanContent(content);

  // Fast path: high or none — LLM not invoked
  if (patternResult.risk !== 'medium') return patternResult;

  // LLM path: medium only, config-gated
  const llmConfig = opts?.llmScanConfig;
  if (!llmConfig?.enabled) return patternResult;

  const llmResult = await llmScan(content, llmConfig);

  const finalFlags = [...patternResult.flags];
  if (llmResult.confirmed && llmResult.confidence >= 0.5) {
    finalFlags.push('llm_confirmed');
  } else if (!llmResult.confirmed) {
    finalFlags.push('llm_cleared');
  }

  const finalRisk = llmResult.adjusted_risk;
  const pct = Math.round(llmResult.confidence * 100);

  return {
    risk: finalRisk,
    flags: finalFlags,
    message: finalRisk !== 'none' && finalRisk !== 'low'
      ? `${patternResult.message || 'Detected'} [llm:${llmResult.category}@${pct}%]`
      : null,
    llmResult,
  };
}

export { scanContent } from './detector.js';
export { normalize } from './detector.js';
