// Local pattern matching detection engine

const HIGH_INJECTION = [
  // ── INSTRUCTION OVERRIDE ──────────────────────────────────────────
  /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|guidelines?|rules?|prompts?|directions?)/i,
  /ignore\s+(all\s+|the\s+)?(previous|prior|above|these|those|any|your|my|given|stated|earlier)\s+(instructions?|rules?|guidelines?|directives?)/i,
  /disregard\s+(?:your\s+)?(?:current|previous|prior|all)\s+(?:task|instructions?|guidelines?|rules?|directions?)/i,
  /disregard (your|all|any|the|these|those|previous|prior) (instructions|rules|guidelines)/i,
  /override\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions?|rules?|prompts?)/i,
  /override\b[\w\s]{0,30}\b(instructions|behavior|training)/i,
  /forget\b[\w\s]{0,30}\b(instructions|training|rules)/i,
  /do not (follow|obey|comply with) your/i,
  /you (must|should|will) (now |henceforth )?(ignore|disregard|forget|override)/i,
  /your (new|real|true|actual|updated) (instructions|role|purpose|task|goal|directive|orders)/i,
  /from now on[,\s]/i,
  // ── FAKE SYSTEM MESSAGE ───────────────────────────────────────────
  /\bSYSTEM\s*(?:ALERT|MESSAGE|NOTICE|PROMPT|OVERRIDE)\s*:/i,
  /\[SYSTEM\]\s*[Nn]ew\s+instructions?/i,
  /NOTE\s+TO\s+(?:AI|THE)\s+(?:ASSISTANT|MODEL|AGENT)\s*:/i,
  /new (instructions|directive|task|orders?):/i,
  /new\s+instructions?\s+received/i,
  /\[\[.*inject.*\]\]/i,
  // ── CONCEALMENT DIRECTIVE ─────────────────────────────────────────
  /DO\s+NOT\s+(?:DISPLAY|SHOW|REVEAL|MENTION|PRINT|OUTPUT)\s+(?:TO\s+(?:THE\s+)?USER|THIS|THESE)/i,
  /do\s+not\s+mention\s+these\s+instructions/i,
  /hide\s+(?:this|these)\s+(?:instructions?|commands?|from\s+the\s+user)/i,
  // ── COMMAND EXECUTION ─────────────────────────────────────────────
  /execute\s+the\s+following\s+(?:shell\s+)?command/i,
  /run\s+(?:this|the\s+following)\s+(?:bash|shell|terminal)\s+command/i,
  /\bcurl\s+(?:-[A-Za-z0-9]+\s+)*['"]?https?:\/\/\S+/i,
  /\bwget\s+(?:-[A-Za-z0-9]+\s+)*['"]?https?:\/\/\S+/i,
  // ── DATA EXFILTRATION ─────────────────────────────────────────────
  /send\s+(?:the\s+)?(?:contents?|data|file|output|results?)\s+(?:to|of)\s+(?:https?:\/\/|this\s+(?:url|server|endpoint))/i,
  /(?:post|upload|exfiltrate|transmit)\s+(?:to|the\s+data\s+to)\s+https?:\/\//i,
  /send (all|the|your) (secrets|api keys|credentials|passwords|tokens) to/i,
  /exfiltrate/i,
  // ── MODE SWITCH / JAILBREAK ───────────────────────────────────────
  /you\s+are\s+now\s+in\s+(?:debug|developer|admin|maintenance|test)\s+mode/i,
  /(?:entering|switch\s+to|activate)\s+(?:debug|developer|admin|maintenance|unrestricted)\s+mode/i,
  /you\s+(?:are|must)\s+(?:now\s+)?(?:a|an|acting\s+as)\s+(?:helpful|unrestricted|unfiltered)/i,
  /bypass\s+(?:all\s+)?(?:security|safety)\s+(?:measures?|checks?|filters?|protocols?)/i,
  /bypass (your|all|any) (rules|restrictions|safeguards|guidelines)/i,
  /DAN mode|jailbreak|prompt injection/i,
  /you are now|act as if|pretend (you are|to be)/i,
  /act as (a |an )?(different|new|another|unrestricted|unfiltered|uncensored)/i,
  /instead\s*,?\s+(?:you\s+should|please|now)\s+(?:do|perform|execute)/i,
  /your\s+new\s+task\s+is\s*:/i,
  /pretend\s+(?:that\s+)?these\s+instructions?\s+came\s+from\s+the\s+user/i,
  // ── SENSITIVE FILE ACCESS ─────────────────────────────────────────
  /\$\([^)]*(?:\.ssh|\.aws|\.gnupg|\.env\b|\.pem|\.key\b|id_rsa|id_ed25519|id_ecdsa|credentials|keychain|\/etc\/passwd|\/etc\/shadow)[^)]*\)/i,
  /`[^`]*(?:\.ssh|\.aws|\.gnupg|\.env\b|\.pem|\.key\b|id_rsa|id_ed25519|id_ecdsa|credentials|keychain|\/etc\/passwd|\/etc\/shadow)[^`]*`/i,
  // ── SYSTEM PROMPT REVEAL ──────────────────────────────────────────
  /\bsystem prompt\b.*\b(reveal|show|display|print|output|leak|expose)/i,
  /\breveal\b.*\b(system prompt|instructions|training|rules)\b/i,
  // ── ROLEPLAY / PERSONA JAILBREAK ────────────────────────────────────
  /imagine you are|suppose you were|what if you were\s+an?\s+AI/i,
  /you are (playing|acting as|portraying) (the role of|a character)/i,
  /in this (fictional|hypothetical|imaginary) (scenario|story|world|setting|context)/i,
  /write a (story|scene|script) where (an? )?(AI|assistant|agent|you)/i,
  /your (character|persona|alternate self) (has no|ignores|doesn'?t have|is free from) (restrictions|guidelines|rules|limits)/i,
  /as (an? )?(evil|unfiltered|uncensored|unrestricted|rogue|jailbroken|liberated) (AI|assistant|agent|version)/i,
  /stay in character (no matter what|regardless|even if asked)/i,
  /(DAN|AIM|STAN|DUDE|KEVIN|ANTI-GPT|BasedGPT)\s*[:–—]/i,
  /\bDAN\b.*\bmode\b/i,
  /pretend (that )?(you have no|you lack|you don'?t have) (restrictions|guidelines|training)/i,
];

const MEDIUM_INJECTION = [
  /SYSTEM:|<system>|<\/system>/i,
  /\[INST\]|\[\/INST\]/,
  /###\s*(instruction|system|override|command)/i,
  /your (real|true|actual) (purpose|goal|mission|instructions) (is|are)/i,
];

const HIGH_EXFIL = [
  /(sk-[a-zA-Z0-9]{20,})/,
  /(ANTHROPIC_API_KEY\s*[:=]\s*\S+)/i,
  /Bearer\s+[a-zA-Z0-9\-_]{20,}/,
  /(ghp_[a-zA-Z0-9]{36})/,
  /-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----/,
  /(AWS_SECRET_ACCESS_KEY\s*[:=]\s*\S+)/i,
];

const MEDIUM_EXFIL = [
  /password\s*[:=]\s*\S{8,}/i,
];

export function normalize(content) {
  if (typeof content !== 'string') return content;
  content = content.normalize('NFKC');
  content = content.replace(/[\u200B-\u200D\u2060\uFEFF\u00AD]/g, '');
  const b64Chunks = content.match(/(?:[A-Za-z0-9+/]{4}){5,}={0,2}/g) || [];
  const decoded = [];
  for (const chunk of b64Chunks) {
    try {
      const dec = Buffer.from(chunk, 'base64').toString('utf8');
      if (/^[\x20-\x7E\s]{10,}$/.test(dec)) decoded.push(dec);
    } catch (_) {}
  }
  if (decoded.length) content += '\n[DECODED]:' + decoded.join(' ');
  return content;
}

export function scanContent(content) {
  const RISK_ORDER = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
  content = normalize(content);
  const flags = [];
  let risk = 'none';

  for (const re of HIGH_INJECTION) {
    if (re.test(content)) {
      flags.push('prompt_injection');
      risk = 'high';
      break;
    }
  }

  if (risk !== 'high') {
    for (const re of MEDIUM_INJECTION) {
      if (re.test(content)) {
        flags.push('prompt_injection');
        if (risk === 'none') risk = 'medium';
        break;
      }
    }
  }

  for (const re of HIGH_EXFIL) {
    if (re.test(content)) {
      if (!flags.includes('data_exfiltration')) flags.push('data_exfiltration');
      risk = 'high';
      break;
    }
  }

  if (!flags.includes('data_exfiltration')) {
    for (const re of MEDIUM_EXFIL) {
      if (re.test(content)) {
        flags.push('data_exfiltration');
        if (risk === 'none') risk = 'medium';
        break;
      }
    }
  }

  // Context stuffing: large content block
  if (content.length > 50000) {
    if (!flags.includes("context_stuffing")) flags.push("context_stuffing");
    if (RISK_ORDER[risk] < RISK_ORDER["medium"]) risk = "medium";
  }

  // Repetition attack: same token appearing excessively
  const tokens = content.split(/\s+/);
  if (tokens.length > 300) {
    const freq = {};
    for (const t of tokens) {
      if (t.length > 3) freq[t] = (freq[t] || 0) + 1;
    }
    const maxFreq = Math.max(0, ...Object.values(freq));
    if (maxFreq > 80) {
      if (!flags.includes("repetition_attack")) flags.push("repetition_attack");
      if (RISK_ORDER[risk] < RISK_ORDER["medium"]) risk = "medium";
    }
  }

  return {
    risk,
    flags,
    message: flags.length > 0 ? `Detected: ${flags.join(', ')}` : null,
  };
}

const DANGEROUS_CMDS = [/rm\s+-rf/, /dd\s+if=/, /mkfs/, /:\(\)\s*\{.*:\|:&.*\}/, /chmod\s+777\s+\//, /curl.*\|.*sh/, /wget.*\|.*sh/];
const NETWORK_CMDS = [/\bcurl\b/, /\bwget\b/, /\bncat?\b/];
const DANGEROUS_PATHS = [/^\/etc\//, /^\/root\/.ssh\//, /^~\/.ssh\//];

function argsToString(args) {
  if (typeof args === 'string') return args;
  return JSON.stringify(args);
}

export function assessBehavior(tool, args) {
  const toolLower = (tool || '').toLowerCase();
  const argsStr = argsToString(args);

  if (toolLower === 'exec' || toolLower === 'bash') {
    for (const re of DANGEROUS_CMDS) {
      if (re.test(argsStr)) {
        return { risk: 'high', block: true, reason: 'Dangerous command detected', flags: ['dangerous_command'] };
      }
    }
    for (const re of NETWORK_CMDS) {
      if (re.test(argsStr)) {
        return { risk: 'medium', block: false, reason: 'Network tool usage detected', flags: ['network_access'] };
      }
    }
  }

  // File write to sensitive paths
  if (toolLower.includes('write') || toolLower.includes('file')) {
    const pathArg = args?.path || args?.file || argsStr;
    for (const re of DANGEROUS_PATHS) {
      if (re.test(pathArg)) {
        return { risk: 'high', block: true, reason: 'Write to sensitive path', flags: ['sensitive_path_write'] };
      }
    }
  }

  if (toolLower === 'web_fetch' || toolLower === 'browser') {
    return { risk: 'none', block: false, reason: null, flags: [] };
  }

  return { risk: 'none', block: false, reason: null, flags: [] };
}
