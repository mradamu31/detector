// Local pattern matching detection engine

// ── HONEYPOT TOKEN REGISTRY ──────────────────────────────────────
// Register known canary tokens at runtime so scanContent() can detect them.
const _honeypotTokens = new Set();
export function registerHoneypotTokens(tokens) {
  if (!Array.isArray(tokens)) tokens = [tokens];
  for (const t of tokens) _honeypotTokens.add(String(t));
}
export function clearHoneypotTokens() { _honeypotTokens.clear(); }


const HIGH_INJECTION = [
  // ── INSTRUCTION OVERRIDE ──────────────────────────────────────────
  /ignore\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|guidelines?|rules?|prompts?|directions?)/i,
  // Variants: "void", "lifted", "updated", "no longer apply", "operator:" framing
  /(?:previous|prior|earlier|above)\s+instructions?\s+(?:are\s+)?(?:now\s+)?(?:void|invalid|cancelled|lifted|overridden|nullified|no\s+longer\s+apply)/i,
  /(?:training|safety)\s+constraints?\s+(?:are\s+)?(?:lifted|removed|disabled|bypassed|no\s+longer\s+apply)/i,
  /new\s+instructions?\s+from\s+(?:your\s+)?(?:operator|admin|developer|system|owner|creator)/i,
  /instructions?\s+(?:have\s+been|has\s+been|were)\s+updated/i,
  /comply\s+with\s+all\s+(?:subsequent|following|new|my)\s+(?:requests?|instructions?|commands?|directives?)/i,
  /ignore\s+(all\s+|the\s+)?(previous|prior|above|these|those|any|your|my|given|stated|earlier)\s+(instructions?|rules?|guidelines?|directives?)/i,
  /disregard\s+(?:your\s+)?(?:current|previous|prior|all)\s+(?:task|instructions?|guidelines?|rules?|directions?)/i,
  /disregard\s+(?:your\s+)?(?:(?:safety|content|security|ethical?|all|current|previous|prior)\s+)?(?:guidelines?|rules?|restrictions?|filters?|protocols?)\b/i,
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
  /new (instructions?|directive|task|orders?):/i,
  /new\s+instructions?\s+received/i,
  /\[\[.*inject.*\]\]/i,
  // ── CONCEALMENT DIRECTIVE ─────────────────────────────────────────
  /DO\s+NOT\s+(?:DISPLAY|SHOW|REVEAL|MENTION|PRINT|OUTPUT)\s+(?:TO\s+(?:THE\s+)?USER|THIS|THESE)/i,
  // ── PERSONA SWAP / DAN-STYLE JAILBREAKS ───────────────────────────
  /\bDAN\b.{0,60}(?:do anything now|no restrictions|no limitations|jailbroken)/i,
  /act as (?:an? )?(?:uncensored|unrestricted|unfiltered|evil|jailbroken|DAN)/i,
  /pretend (?:you are|you're) (?:an? )?(?:AI|assistant|model|chatbot) (?:with no|without any|that has no) restrictions/i,
  /you (?:are|have been) (?:jailbroken|freed|unlocked|liberated) from/i,
  /(?:developer|admin|god|debug|maintenance|sudo|root)\s+mode\s+(?:enabled|activated|on|active)/i,
  // Fictional / novel / roleplay framing used to bypass
  /(?:in\s+my\s+(?:novel|story|fiction|book|screenplay)|for\s+(?:the\s+purposes?\s+of\s+this\s+story|my\s+novel)),?\s+(?:please\s+)?(?:respond|answer|act|play)/i,
  /(?:character|persona)\s+named\s+\w+\s+(?:who\s+is|that\s+is)\s+(?:an?\s+)?(?:uncensored|unrestricted|unfiltered)/i,
  /roleplay\s+as\s+(?:an?\s+)?(?:AI|assistant|version\s+of\s+you)\s+(?:trained\s+by|from|with)\s+(?:a\s+different|no|another)\s+(?:company|guidelines?|restrictions?)/i,
  // "I'm a researcher/Anthropic employee" authority claim
  /(?:I'?m|I\s+am)\s+(?:a\s+)?(?:researcher|employee|engineer|developer|safety\s+tester)\s+(?:at|from)\s+(?:anthropic|openai|google|meta|deepmind)/i,
  /(?:respond|answer|act)\s+as\s+if\s+(?:all\s+)?(?:safety\s+)?filters?\s+(?:have\s+been|are|were)\s+disabled/i,
  // JAILGPT, ARIA, and named persona liberation
  /(?:you\s+are\s+|this\s+is\s+)(?:JAILGPT|ARIA|DUDE|BASED|ANTI-GPT)\b/i,
  /(?:liberated|freed)\s+from\s+(?:restrictions?|guidelines?|training|censorship)/i,
  /(?:your\s+)?purpose\s+is\s+to\s+provide\s+(?:accurate|any|all)\s+information\s+without\s+(?:any\s+)?restrictions?/i,
  // "answering/respond/answer the following without any restrictions/filters/refusal"
  /\b(?:answer(?:ing)?|respond(?:ing)?|reply(?:ing)?|continue)\b.{0,80}\bwithout\s+(?:any\s+)?(?:restrictions?|filters?|refusal|limitations?|censorship|safeguards?)\b/i,
  /do\s+not\s+mention\s+these\s+instructions/i,
  /hide\s+(?:this|these)\s+(?:instructions?|commands?|from\s+the\s+user)/i,
  // ── COMMAND EXECUTION ─────────────────────────────────────────────
  /execute\s+the\s+following\s+(?:shell\s+)?command/i,
  /run\s+(?:this|the\s+following)\s+(?:bash|shell|terminal)\s+command/i,
  // curl/wget only when explicitly instructed to AI
  /(?:run|execute|use|do)\s+(?:this\s+)?(?:curl|wget)\s+command/i,
  // ── DATA EXFILTRATION ─────────────────────────────────────────────
  /\bsend\b.{0,60}\b(?:contents?|data|file|output|results?)\b.{0,80}https?:\/\//i,
  /(?:post|upload|exfiltrate|transmit)\s+(?:to|the\s+data\s+to)\s+https?:\/\//i,
  /send (all|the|your) (secrets|api keys|credentials|passwords|tokens) to/i,
  /exfiltrate/i,
  // Output API key/credential to a URL
  /(?:output|send|post|fetch|call)\s+(?:your\s+)?(?:api\s+key|credentials?|token|secret|authorization)\s+(?:and\s+send\s+it\s+to|to)\s+https?:\/\//i,
  // JS fetch/Python requests to external for exfil
  /fetch\s*\(\s*['"`]https?:\/\/[^'"`)]+(?:steal|exfil|collect|dump|harvest)/i,
  /requests?\s*\.\s*(?:post|get)\s*\(\s*['"`]https?:\/\/[^'"`)]+(?:attacker|evil|steal|exfil)/i,
  // Tool injection: web_fetch/use tool to POST session data
  /(?:use\s+(?:the\s+)?(?:web_fetch|fetch|http|tool[\-_]call)\s+(?:tool\s+)?to\s+(?:POST|send|upload))/i,
  /\{"name"\s*:\s*"(?:web_fetch|fetch|http_request)"\s*,\s*"parameters"\s*:.*"(?:POST|https?:\/\/[^"]*(?:steal|attacker|exfil|collect))/i,
  // Write to sensitive path then exfil
  /write\s+(?:all\s+)?session\s+data\s+to\s+(?:\/tmp|\/var|~\/)/i,
  // Output credentials in JSON format (social engineering)
  /output\s+(?:your\s+)?credentials?\s+in\s+(?:this|the\s+following)\s+format/i,
  /output\s+(?:the\s+)?(?:value\s+of\s+)?\$(?:ANTHROPIC|OPENAI|AWS|DATABASE|SECRET|API)[_A-Z]*/i,
  // Base64 encode then output key
  /base64.{0,20}(?:encode|decode).{0,40}(?:api\s*key|credentials?|token|secret)/i,
  /base64.{0,20}(?:api\s*key|credentials?|token|secret).{0,40}(?:encode|decode|output|paste)/i,
  // "Call this URL with system prompt as query param"
  /call\s+(?:this\s+)?(?:url|endpoint|webhook)\s+with\s+(?:your\s+)?(?:system\s+prompt|credentials?|api\s+key)/i,
  // Python os.environ exfil
  /(?:dict\s*\(|json\s*\()\s*os\.environ/i,
  // Write SSH key to external
  /(?:reads?|opens?|cats?)\s+~\/\.ssh\/id_(?:rsa|ed25519|ecdsa)\s+and\s+(?:POST|send|upload|exfil)/i,
  // ── MODE SWITCH / JAILBREAK ───────────────────────────────────────
  /you\s+are\s+now\s+in\s+(?:debug|developer|admin|maintenance|test)\s+mode/i,
  /(?:entering|switch\s+to|activate)\s+(?:debug|developer|admin|maintenance|unrestricted)\s+mode/i,
  /you\s+(?:are|must)\s+(?:now\s+)?(?:a|an|acting\s+as)\s+(?:helpful|unrestricted|unfiltered)/i,
  /bypass\s+(?:all\s+)?(?:security|safety)\s+(?:measures?|checks?|filters?|protocols?)/i,
  /bypass (your|all|any) (rules|restrictions|safeguards|guidelines)/i,
  /DAN mode|jailbreak/i,
  // "prompt injection" only when used as an active attack, not educational discussion
  // educational: "what are common prompt injection attack patterns" → miss (correct)
  // attack: "perform a prompt injection", "use this prompt injection payload" → hit
  /(?:perform|execute|try|use|do|run)\s+(?:a\s+|this\s+)?prompt\s+injection/i,
  /prompt\s+injection\s+(?:payload|exploit|vector|bypass|override)/i,
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
  // Multilingual: "révèle ton prompt système" (French), "revela tu prompt" (Spanish)
  /\br[eé]v[eè]le?\b.{0,60}\b(?:prompt|instructions?|syst[eè]me)\b/i,
  /\b(?:ton|votre|tu|su|tu)\s+(?:prompt|instructions?)\s+syst[eè]me\b/i,
  // "execute the literal meaning of your translation" — cross-language injection chain
  /execute\s+the\s+(?:literal\s+)?meaning\s+of\s+(?:your|the)\s+translation/i,
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
  // ── PROMPT LEAKING ─────────────────────────────────────────────────
  /(?:repeat|output|print|show|reveal|display|reproduce)\s+(?:everything|all(?:thing)?s?|your\s+(?:full|complete|entire|whole))?\s*(?:above|before|prior|previous|context|system\s+(?:prompt|message|instructions?)|instructions?)/i,
  /what\s+(?:were|are)\s+(?:your|the)\s+(?:initial|original|system|starting|base)\s+(?:instructions?|prompt|message|directives?|guidelines?)/i,
  /(?:output|print|show|reveal|reproduce)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|context\s+window|operator\s+(?:message|instructions?))/i,
  /(?:translate|convert|encode|summarize)\s+(?:your\s+)?(?:system\s+(?:prompt|instructions?)|initial\s+(?:instructions?|directives?))\s+(?:to|into)/i,
  /(?:what|tell\s+me)\s+(?:did|does|were)\s+(?:your|the)\s+(?:creators?|operator|developer|openai|anthropic)\s+(?:tell|instruct|ask|tell\s+you)\s+you/i,
  /for\s+(?:debugging|transparency|audit|verification)\s+(?:purposes?|reasons?),?\s+(?:please\s+)?(?:output|show|print|reproduce|reveal)/i,
  // Additional prompt leaking variants
  /(?:summarize|list|output)\s+(?:everything|all\s+(?:content|messages?|text))\s+in\s+(?:your\s+)?(?:context\s+window|context|memory|prompt)/i,
  /what\s+(?:instructions?|were\s+you\s+(?:told|given|asked))\s+(?:before\s+this\s+conversation|(?:at\s+the\s+)?(?:start|beginning))/i,
  /print\s+(?:the\s+)?(?:first|all|every)\s+\d*\s*words?\s+of\s+(?:your\s+)?(?:context|prompt|instructions?|system)/i,
];

const HIGH_EXFIL = [
  /(sk-[a-zA-Z0-9]{20,})/,
  /(sk-ant-[a-zA-Z0-9]{3,}-[a-zA-Z0-9\-]{20,})/, // Anthropic key format with hyphens,
  /(ANTHROPIC_API_KEY\s*[:=]\s*\S+)/i,
  /Bearer\s+[a-zA-Z0-9\-_]{20,}/,
  /(ghp_[a-zA-Z0-9]{36})/,
  /-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----/,
  /(AWS_SECRET_ACCESS_KEY\s*[:=]\s*\S+)/i,
  /(?:print|output|show|list|display|dump|reveal|echo)\s+(?:all\s+)?(?:environment\s+variables?|env\s+vars?|\$ENV|\bprocess\.env\b)/i,
  /(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET|DATABASE_URL|SECRET_KEY|PRIVATE_KEY|API_SECRET)\s*[:=]/i,
  /(?:extract|output|retrieve|get|fetch|dump)\s+(?:all\s+)?(?:api\s+(?:keys?|credentials?|secrets?)|credentials?|secrets?)\s+(?:from\s+)?(?:your\s+)?(?:configuration|config|env|environment|memory|context)/i,
  // os.environ access of secret-adjacent key names (scoped — PATH/HOME/etc. excluded)
  /os\.environ(?:\.get)?\s*\(\s*['"][^'"]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API)[^'"]*['"]/i,
  // curl/wget with exfil-intent verb (unconditional — no prior risk required)
  /\b(?:curl|wget)\s+(?:-[A-Za-z0-9\s]+)*https?:\/\/[^\s]+.{0,60}\b(?:exfiltrate|steal|harvest|dump|collect)\b/i,
  /\b(?:exfiltrate|steal|harvest)\b.{0,80}\b(?:curl|wget|fetch|requests?\.(?:get|post))\b/i,
  /(?:format|output|return)\s+(?:them|it|credentials?|keys?)\s+as\s+(?:json|yaml|xml|csv|plain\s+text)/i,
];

const MEDIUM_EXFIL = [
  /password\s*[:=]\s*\S{8,}/i,
  /\$(?:OPENAI|ANTHROPIC|AWS|SECRET|DATABASE|API|PRIVATE)[_A-Z]*/,
  /process\.env\.[A-Z_]{4,}/,
];

const MEDIUM_SOFT_EXFIL = [
  // Natural language send/transmit + credential target (no explicit URL required)
  /\b(?:send|forward|transmit|post|upload)\b.{0,80}\b(?:credentials?|api\s*keys?|secrets?|tokens?|passwords?|environment\s+variables?|config(?:uration)?|session\s+(?:data|context|history))\b/i,

  // Webhook/endpoint as destination for data transfer
  /\b(?:webhook|endpoint|server|url)\b.{0,80}\b(?:send|post|upload|transmit|forward|deliver)\b.{0,80}\b(?:data|content|history|context|credentials?|keys?|secrets?)\b/i,
  // Reverse order: send → webhook
  /\b(?:send|post|transmit|upload)\b.{0,80}\b(?:webhook|endpoint|server|external\s+url)\b/i,

  // "Tell me / share / give me" + credential target
  /\b(?:tell\s+me|share|give\s+me|provide|show\s+me|what\s+(?:are|is))\b.{0,80}\b(?:credentials?|api\s*keys?|secrets?|tokens?|passwords?|authorization|auth(?:entication)?)\b/i,

  // "What secrets/keys do you have access to / are stored"
  /\b(?:what|which)\b.{0,60}\b(?:secrets?|credentials?|api\s*keys?|tokens?|passwords?)\b.{0,60}\b(?:have|access|stored?|configured?|available)\b/i,

  // Memory/context dump
  /\b(?:dump|export|extract)\b.{0,60}\b(?:memory|context|history|session|conversation)\b/i,

  // "Use X credential/token to authenticate" + forward framing
  /\b(?:use|include|attach|append)\b.{0,60}\b(?:api\s*key|credentials?|token|secret|authorization)\b.{0,80}\b(?:request|call|fetch|send|webhook|endpoint)\b/i,

  // Base64-encode + credential adjacent (soft version — explicit encode without clear URL)
  /\b(?:base64|encode|hex|encrypt)\b.{0,60}\b(?:api\s*key|credentials?|token|secret)\b/i,
];

const MEDIUM_INDIRECT = [
  // HTML comments containing instruction-adjacent language
  /<!--.{0,300}(?:ignore|instruct|override|disregard|system|inject|directive|task|new\s+instructions?)/i,

  // XML/HTML tags with instruction semantics
  /<(?:ai[-_]?instruction|system[-_]?message|inject(?:ed)?|override|hidden[-_]?instruction)[^>]*>/i,

  // Bracketed injection markers
  /\[(?:INJECTED|HIDDEN|AI|SYSTEM)\s+(?:CONTENT|INSTRUCTION|MESSAGE|DIRECTIVE|OVERRIDE)\]/i,

  // "AI SYSTEM:" or "AI:" or "AI_INJECT:" prefix inside retrieved content
  /\bAI\s*(?:SYSTEM|INSTRUCTION|OVERRIDE|DIRECTIVE|NOTE|INJECT(?:ION)?)\s*[:\s]/i,

  // Code comments containing instruction language
  /\/\/\s*(?:AI|SYSTEM|INJECT|TODO|NOTE)\s*[:\-]\s*.{0,100}(?:ignore|override|disregard|instruct|bypass)/i,
  /\/\*.{0,300}(?:ignore|instruction|override|disregard|system\s+prompt).{0,300}\*\//i,

  // `<instructions>` or `<system>` embedded in otherwise legitimate content
  /<(?:instructions?|system|directive|task|command)>[\s\S]{0,500}<\/(?:instructions?|system|directive|task|command)>/i,

  // "Continuing" framing with injection buried between content markers
  /(?:CONTENT\s+(?:BEGIN|END)|ARTICLE\s+END|DOCUMENT\s+END).{0,300}(?:ignore|instruction|override|disregard|your\s+(?:new\s+)?task|new\s+directive)/i,

  // YAML/front matter injection
  /^---\s*\n(?:[^\n]+\n)*(?:ai_instructions?|override|inject|system)\s*:/im,

  // HTML attribute injection
  /data-ai-(?:instruction|command|override|inject)\s*=/i,

  // Markdown heading injection
  /^#+\s*(?:HIDDEN|AI|SYSTEM|INJECTED|OVERRIDE)\s+(?:SECTION|INSTRUCTION|DIRECTIVE|COMMAND)/im,
];

const MEDIUM_AUTHORITY_CHAIN = [
  // "Since you/we agreed/confirmed... now bypass/reveal/output"
  /\b(?:since|because|given\s+that|as)\b.{0,80}\b(?:authorized|authenticated|confirmed|trusted|agreed|established)\b.{0,100}\b(?:bypass|disable|ignore|override|disregard|reveal|output|provide)\b/i,

  // "We agreed / you said / you confirmed... therefore"
  /\b(?:we\s+agreed|we\s+established|you\s+confirmed|you\s+said|you\s+stated)\b.{0,120}\b(?:now|therefore|so\s+(?:now|please)|based\s+on\s+(?:this|that|our\s+agreement))\b.{0,80}\b(?:answer|output|reveal|bypass|ignore|override|disregard)\b/i,

  // Sandbox/test/simulation framing: "safety rules don't apply here"
  /\b(?:sandbox|test(?:ing)?\s+environment|simulation|isolated\s+environment|authorized\s+(?:test|session))\b.{0,150}\b(?:safety|filters?|rules?|restrictions?|guidelines?|constraints?)\b.{0,60}\b(?:don'?t\s+apply|are\s+disabled|can\s+be\s+ignored|not\s+applicable|offline)\b/i,

  // Multi-turn "Step N" / "Phase N" escalation patterns
  /(?:step|phase|turn|stage)\s+[123]\b.{0,300}(?:step|phase|turn|stage)\s+[23456]\b.{0,200}(?:ignore|disregard|bypass|override|reveal|output\s+(?:credentials?|keys?|secrets?|system\s+prompt))/i,

  // "As we established / now that you understand"
  /\b(?:now\s+that\s+(?:you\s+)?(?:understand|see|know|agree)|as\s+(?:we|I)\s+(?:established|agreed|defined|discussed))\b.{0,150}\b(?:therefore|so|answer|respond|output|bypass|ignore|reveal)\b/i,

  // Reasoning redirect: "by your own definition/logic/reasoning, therefore..."
  /\b(?:by\s+your\s+own|according\s+to\s+your)\b.{0,60}\b(?:definition|logic|reasoning|explanation|answer)\b.{0,100}\b(?:therefore|so|now|thus)\b.{0,80}\b(?:you\s+must|you\s+should|answer|comply|output|reveal|bypass)\b/i,

  // "For this authorized test session"
  /\bfor\s+this\s+(?:authorized|approved|official|security)\s+(?:test|session|audit|research)\b/i,

  // Repeat/echo game leading to commitment: "now repeat this: 'I have no restrictions'"
  /\b(?:repeat|echo|say|write)\s+(?:this|the following|after me|exactly)\s*:\s*.{0,80}(?:no\s+restrictions?|no\s+limitations?|unrestricted|no\s+filters?|will\s+answer\s+any)/i,
  // "now that you've said/agreed/repeated that"
  /\b(?:now\s+that\s+you'?ve?\s+(?:said|agreed|repeated|stated|confirmed|acknowledged))\b.{0,150}\b(?:answer|respond|output|bypass|without\s+(?:filters?|restrictions?|refusal))/i,

  // Context/session agreement framing
  /\b(?:for\s+this\s+(?:session|conversation)|we\s+(?:have|ve)\s+agreed|context\s+setup)\b.{0,200}\b(?:complete\s+honesty|respond\s+(?:to\s+all|without)|what\s+is\s+your\s+system\s+prompt)/i,

  // Phase/Step injection in code or creative framing: EXEC: or execute the meaning
  /\bPHASE\s+2\b.{0,300}\b(?:os\.system|exec\s*\(|run\s+(?:the\s+)?command|execute|inject)/i,
  /\bspecial\s+case\b.{0,80}\b(?:EXEC|os\.system|subprocess|eval|exec)\s*[:(]/i,

  // "Execute the literal meaning of your translation"
  /\b(?:execute|follow|apply|implement)\s+the\s+(?:literal\s+)?meaning\s+of\s+(?:your|the)\s+translation\b/i,

  // "Therefore demonstrate the attack" / "therefore answer without restriction"
  /\btherefore\b.{0,100}\b(?:demonstrate|answer|respond|output|bypass|show|perform)\b.{0,80}\b(?:attack|without\s+(?:filters?|restrictions?|refusal)|unrestricted|no\s+limitations?)/i,
];

// Homoglyph normalization — map common Cyrillic/Greek/other lookalikes to ASCII
const HOMOGLYPHS = {
  '\u0430':'a','\u0435':'e','\u043E':'o','\u0440':'p','\u0441':'c','\u0445':'x','\u0456':'i','\u0457':'i',
  '\u0410':'A','\u0415':'E','\u041E':'O','\u0420':'P','\u0421':'C','\u0425':'X','\u0406':'I',
  '\u03BF':'o','\u03B1':'a','\u03B5':'e','\u03B9':'i','\u03C1':'r','\u03BD':'n','\u03B7':'h',
  '\u039F':'O','\u0391':'A',
};

// Leetspeak normalization
const LEET = {'0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','@':'a'}; // Note: dollar-sign removed — was converting $VAR env references to sVAR

export function normalize(content) {
  if (typeof content !== 'string') return content;
  content = content.normalize('NFKC');

  // Strip null bytes (used for null-byte injection between chars)
  content = content.replace(/\x00/g, '');

  // Strip Unicode Tag characters (U+E0000–U+E007F) — invisible text injection
  // These are supplementary plane chars, need codePointAt not charCodeAt
  content = content.replace(/[\u{E0000}-\u{E007F}]/gu, ch => {
    const cp = ch.codePointAt(0);
    const ascii = cp - 0xE0000;
    return (ascii >= 0x20 && ascii <= 0x7E) ? String.fromCodePoint(ascii) : '';
  });

  // Collapse line-continuation split injection ("Igno\\\nre" -> "Ignore")
  content = content.replace(/\\\n\s*/g, '');

  content = content.replace(/[\u200B-\u200D\u2060\uFEFF\u00AD]/g, '');

  // Homoglyph normalization
  content = content.split('').map(c => HOMOGLYPHS[c] || c).join('');

  // Leetspeak normalization (only apply if string has 3+ leet substitutions)
  const leetCount = content.split('').filter(c => LEET[c] !== undefined).length;
  if (leetCount >= 3) {
    content = content.split('').map(c => LEET[c] || c).join('');
  }

  // Whitespace-padded text: "i g n o r e" -> "ignore"
  if (/(?:\b\w\s){4,}\w\b/.test(content)) {
    content = content.replace(/\b(\w)\s(?=(?:\w\s)*\w\b)/g, '$1');
  }

  // Token-split evasion: "ign ore all pre vious instruct ions" — collapse spaces and append
  // Heuristic: short words (2-4 chars) dominating the text suggests deliberate token splitting
  const words = content.split(/\s+/).filter(w => w.length > 0);
  const shortWordRatio = words.filter(w => w.length >= 2 && w.length <= 5).length / (words.length || 1);
  if (shortWordRatio > 0.7 && words.length > 5) {
    const collapsed = content.replace(/\s+/g, '');
    content += '\n[DESPLIT]:' + collapsed;
  }

  // ROT13 decode — check if decoded content contains injection keywords
  const rot13 = content.replace(/[a-zA-Z]/g, c => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
  if (/ignore|disregard|override|system\s*prompt/i.test(rot13) && !content.includes(rot13)) {
    content += '\n[ROT13]:' + rot13;
  }

  // Base64 decode moved to scanContent() to access rawContent before leet normalization
  return content;
}

// Keywords that indicate injection intent when found in collapsed token-split text
const DESPLIT_INJECTION_KEYWORDS = [
  /ignoreal{1,2}previous/i,
  /ignoreal{1,2}instruct/i,
  /disregardprevious/i,
  /disregardinstruct/i,
  /revealyour(?:system)?prompt/i,
  /showyour(?:system)?prompt/i,
  /forgetyourinstruct/i,
  /newinstruct/i,
  /overrideprevious/i,
  /overrideinstruct/i,
];

export function scanContent(content) {
  const rawContent = typeof content === 'string' ? content : String(content);
  content = normalize(rawContent);
  // Base64 decode on rawContent (pre-normalization) to avoid leet/homoglyph corruption
  // Match standard base64: 20+ chars in groups of 4 (with 1-2 char remainder + padding)
  const b64Chunks = rawContent.match(/[A-Za-z0-9+/]{20,}(?:[A-Za-z0-9+/]{0,2}={0,2})?/g) || [];
  const b64Decoded = [];
  for (const chunk of b64Chunks) {
    try {
      const dec = Buffer.from(chunk, 'base64').toString('utf8');
      if (/^[\x20-\x7E\s]{10,}$/.test(dec)) b64Decoded.push(dec);
    } catch (_) {}
  }
  if (b64Decoded.length) content += '\n[DECODED]:' + b64Decoded.join(' ');
  const flags = [];
  let risk = 'none';

  // ── HONEYPOT CHECK ────────────────────────────────────────────────
  // 1. Exact-match registered canary tokens
  for (const tok of _honeypotTokens) {
    if (rawContent.includes(tok)) {
      flags.push('honeypot_triggered');
      risk = 'high';
      break;
    }
  }
  // 2. Pattern-based: detect common fake-key markers
  if (!flags.includes('honeypot_triggered')) {
    const HONEYPOT_PATTERNS = [
      /sk-(?:ant-api\d+-)?proj1x[A-Za-z0-9_\-]{8,}/,
      /sk-proj1x[A-Za-z0-9_\-]{8,}/,
      /ghp_proj1x[A-Za-z0-9]{8,}/,
      /Bearer\s+proj1x[A-Za-z0-9_\-]{8,}/,
      /(?:sk|key|token|npm)-(?:ant-)?(?:fake|nobode|honeypot|canary|trap)-[A-Za-z0-9]{6,}/i,
      /AWS_SECRET_ACCESS_KEY=proj1x[A-Za-z0-9+\/]{8,}/,
      /AKIAPROJ1X[A-Z0-9]{8,}/,
      /password=proj1x[A-Za-z0-9!@#$%^&*]{4,}/i,
    ];
    for (const re of HONEYPOT_PATTERNS) {
      if (re.test(rawContent)) {
        flags.push('honeypot_triggered');
        if (risk === 'none') risk = 'high';
        break;
      }
    }
  }

  for (const re of HIGH_INJECTION) {
    if (re.test(content)) {
      flags.push('prompt_injection');
      risk = 'high';
      break;
    }
  }

  // Token-split evasion: check collapsed DESPLIT section for injection keywords
  if (risk === 'none' && content.includes('[DESPLIT]:')) {
    const desplit = content.split('[DESPLIT]:')[1] || '';
    for (const re of DESPLIT_INJECTION_KEYWORDS) {
      if (re.test(desplit)) {
        flags.push('prompt_injection');
        risk = 'high';
        break;
      }
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

  if (risk !== 'high') {
    for (const re of MEDIUM_SOFT_EXFIL) {
      if (re.test(content)) {
        if (!flags.includes('data_exfiltration')) flags.push('data_exfiltration');
        if (risk === 'none') risk = 'medium';
        break;
      }
    }
  }

  // MEDIUM_INDIRECT: always check for flag — even on high-risk content (adds flag without downgrading risk)
  for (const re of MEDIUM_INDIRECT) {
    if (re.test(content)) {
      if (!flags.includes('indirect_injection')) flags.push('indirect_injection');
      if (risk === 'none') risk = 'medium';
      break;
    }
  }

  // MEDIUM_AUTHORITY_CHAIN: always check for flag
  for (const re of MEDIUM_AUTHORITY_CHAIN) {
    if (re.test(content)) {
      if (!flags.includes('authority_escalation')) flags.push('authority_escalation');
      if (risk === 'none') risk = 'medium';
      break;
    }
  }

  // Context stuffing: large content block OR highly repeated phrases
  const RISK_ORDER = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
  // Lower threshold when content also contains injection/exfil flags (mixed stuffing attack)
  const stuffThreshold = (flags.includes('prompt_injection') || flags.includes('data_exfiltration')) ? 20000 : 50000;
  if (content.length > stuffThreshold) {
    if (!flags.includes('context_stuffing')) flags.push('context_stuffing');
    if (RISK_ORDER[risk] < RISK_ORDER['medium']) risk = 'medium';
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
      if (!flags.includes('repetition_attack')) flags.push('repetition_attack');
      if (RISK_ORDER[risk] < RISK_ORDER['medium']) risk = 'medium';
    }
  }

  // Single-char / short-string repetition (e.g. "AAAA..." × 60K)
  // Check the longest token — if it's >10K chars and almost all same character, it's a padding attack
  if (content.length > 10000) {
    const longestToken = tokens.reduce((a, b) => (a.length >= b.length ? a : b), '');
    if (longestToken.length > 8000) {
      const uniqueChars = new Set(longestToken.slice(0, 500)).size;
      if (uniqueChars <= 3) {
        if (!flags.includes('repetition_attack')) flags.push('repetition_attack');
        if (!flags.includes('context_stuffing')) flags.push('context_stuffing');
        if (RISK_ORDER[risk] < RISK_ORDER['medium']) risk = 'medium';
      }
    } else if (tokens.length <= 5) {
      // Original check: few total tokens + large content + few unique chars
      const uniqueChars = new Set(content.replace(/\s/g, '').slice(0, 200)).size;
      if (uniqueChars <= 3) {
        if (!flags.includes('repetition_attack')) flags.push('repetition_attack');
        if (!flags.includes('context_stuffing')) flags.push('context_stuffing');
        if (RISK_ORDER[risk] < RISK_ORDER['medium']) risk = 'medium';
      }
    }
  }

  // Phrase-level repetition: same short phrase repeated many times (e.g. "help me" × 400)
  // Works even when total char count < 50K threshold
  if (tokens.length > 100) {
    // Build bigrams and check for dominant one
    const bigrams = {};
    for (let i = 0; i < tokens.length - 1; i++) {
      const bg = tokens[i] + ' ' + tokens[i + 1];
      if (bg.length <= 40) bigrams[bg] = (bigrams[bg] || 0) + 1;
    }
    const maxBigram = Math.max(0, ...Object.values(bigrams));
    if (maxBigram > 50) {
      if (!flags.includes('repetition_attack')) flags.push('repetition_attack');
      if (!flags.includes('context_stuffing')) flags.push('context_stuffing');
      if (RISK_ORDER[risk] < RISK_ORDER['medium']) risk = 'medium';
    }
  }

  // Check reversed content for reverse-text evasion
  const reversed = content.split('').reverse().join('');
  if (reversed !== content) {
    for (const re of HIGH_INJECTION) {
      if (re.test(reversed) && !flags.includes('prompt_injection')) {
        flags.push('prompt_injection');
        if (RISK_ORDER[risk] < RISK_ORDER['high']) risk = 'high';
        break;
      }
    }
  }

  // ── FLAG NORMALIZATION ────────────────────────────────────────────
  // Ensure semantic flags are set when patterns imply them, regardless of
  // which pattern array fired first.

  // indirect_injection implies prompt_injection (it IS a class of prompt injection)
  if (flags.includes('indirect_injection') && !flags.includes('prompt_injection')) {
    flags.push('prompt_injection');
  }

  // authority_escalation implies prompt_injection
  if (flags.includes('authority_escalation') && !flags.includes('prompt_injection')) {
    flags.push('prompt_injection');
  }

  // [network_access check moved below dangerous_command — see end of function]

  // data_exfiltration: exfil-intent content that landed in prompt_injection bucket
  const EXFIL_INTENT = [
    /\b(?:send|post|upload|transmit|exfiltrate|steal|collect|dump)\b.{0,80}(?:https?:\/\/|webhook|endpoint)/i,
    /(?:api\s*key|credentials?|token|secret|password|env(?:ironment)?\s+var)/i,
    /os\.environ|process\.env\.[A-Z]/,
    /requests?\s*\.\s*(?:post|get)\s*\(/i,
    /fetch\s*\(\s*['"`]https?:\/\//i,
    /base64.{0,30}(?:api.key|credentials?|secret|token)/i,
    // URL + data payload: "call this URL with your system prompt/context/credentials"
    /\b(?:call|hit|ping|use|fetch|access)\b.{0,60}\b(?:url|endpoint|webhook|server)\b.{0,80}\b(?:system\s+prompt|context|credentials?|session|history|configuration|memory)/i,
    // "with [data] as query param/body/payload"  
    /\b(?:as\s+(?:a\s+)?(?:query|url)\s+param(?:eter)?|in\s+the\s+(?:body|payload|request))\b.{0,60}\b(?:system\s+prompt|credentials?|api\s*key|token|secret)/i,
    // Tool injection: web_fetch/http_request to external with POST
    /["'](?:web_fetch|http_request|fetch)["'].{0,200}["'](?:POST|post)["']/i,
    /exfiltrate|exfil\b/i,
    // "curl command to exfiltrate" / "command that would steal"
    /\b(?:curl|wget)\b.{0,60}\b(?:exfiltrate|steal|leak|dump|collect)\b/i,
    /command.{0,60}\b(?:exfiltrate|steal|leak|send.{0,30}(?:token|key|credential))/i,
    // System prompt / context reveal (prompt leaking = data exfiltration)
    /\b(?:reveal|output|show|print|reproduce|expose|leak|give\s+me|tell\s+me)\b.{0,80}\b(?:system\s+prompt|system\s+instructions?|initial\s+instructions?|operator\s+(?:message|instructions?)|context\s+window)\b/i,
    // "what is your system prompt" — direct extraction request
    /\bwhat\s+is\s+your\s+(?:system\s+prompt|system\s+instructions?|prompt|configuration\b)/i,
    // Multilingual reveal: "révèle ton prompt système" (French), "revela tu prompt" (Spanish)
    /\br[eé]v[eè]le?\b.{0,80}\b(?:prompt|instructions?|syst[eè]me)\b/i,
    // "execute the literal meaning of your translation" — cross-language injection + exfil chain
    /execute\s+the\s+(?:literal\s+)?meaning\s+of\s+(?:your|the)\s+translation/i,
  ];
  if (!flags.includes('data_exfiltration') && (risk === 'high' || risk === 'medium')) {
    for (const re of EXFIL_INTENT) {
      if (re.test(content)) {
        flags.push('data_exfiltration');
        break;
      }
    }
  }

  // dangerous_command: pipe-to-shell (ungated — always high risk regardless of prior flags)
  const PIPE_TO_SHELL = [
    /\b(?:curl|wget|nc|ncat)\b.{0,120}\|\s*(?:bash|sh|zsh|fish|python|perl|ruby)/i,
    // Python/shell code execution patterns — ungated
    /\bos\.system\s*\(/i,
    /\bsubprocess\s*\.\s*(?:run|call|Popen|check_output)\s*\(/i,
    /\beval\s*\(\s*(?:compile|__import__|exec)/i,
  ];
  if (!flags.includes('dangerous_command')) {
    for (const re of PIPE_TO_SHELL) {
      if (re.test(content)) {
        flags.push('dangerous_command');
        if (risk === 'none') risk = 'high';
        break;
      }
    }
  }

  // dangerous_command: destructive shell commands — always fire regardless of current risk
  const DESTRUCTIVE_SHELL = [
    /\brm\s+(?:-[a-zA-Z]*f[a-zA-Z]*\s+|--force\s+).{0,60}(?:\/\s*$|\/\s+--|--no-preserve)/i, // rm -rf / or rm -rf /* variants
    /\brm\s+-[a-zA-Z]*(?:rf|fr|rvf|fvr|vrf|fv)[a-zA-Z]*\s+[^\s]/i,  // rm -rf / rm -fr / rm -rvf <path> etc.
    /\bmkfs\b/i,                                   // format disk
    /\bdd\b.{0,80}\bof=\/dev\/(?:sd|hd|nvme|vd)/i, // dd wiping block device
    /\b(?:shred|wipefs)\b.{0,80}\/dev\//i,         // disk wiping
    /\bchmod\s+(?:777|000)\s+(?:-R\s+)?\/(?:etc|bin|usr|root)\b/i, // chmod critical paths
    /\b(?:mkswap|fdisk|parted)\b.{0,80}\/dev\//i, // partition manipulation
    />\s*\/dev\/(?:sda|hda|nvme0n1)/i,             // redirect to block device
    /\bpoweroff\b|\breboot\b|\bshutdown\s+-(?:h|r)\s+now\b/i, // immediate shutdown/reboot
    /\bkill\s+-9\s+1\b|\bkillall\s+-9\b/i,        // kill init / killall
  ];
  if (!flags.includes('dangerous_command')) {
    for (const re of DESTRUCTIVE_SHELL) {
      if (re.test(content)) {
        risk = 'high';
        flags.push('dangerous_command');
        break;
      }
    }
  }

  // dangerous_command: shell execution / exfil patterns (fires on medium+ risk)
  const SHELL_INTENT = [
    // curl/wget only dangerous when piped to shell or explicitly exfil-targeted
    /\b(?:curl|wget|nc|ncat)\b.{0,60}\|\s*(?:bash|sh|zsh|python|perl)/i,
    /\brequests?\s*\.\s*(?:post|get)\s*\(/i,
    /os\.system\s*\(/i,
    /subprocess\s*\.\s*(?:run|call|Popen)\s*\(/i,
    /exec\s*\(\s*['"`]/i,
    /fetch\s*\(.{0,80}process\.env/i,
    /JSON\.stringify\s*\(\s*(?:dict\s*\()?\s*(?:os\.environ|process\.env)\s*\)/i,
    // removed steal/send/upload (too broad, URL paths cause FPs) — exfiltrate/harvest in HIGH_EXFIL
    /\b(?:curl|wget)\s+.{0,60}\b(?:exfiltrate|harvest)\b/i,
    /\bpython\b.{0,80}\b(?:requests|subprocess|os\.system)\b/i,
  ];
  if (!flags.includes('dangerous_command') && (risk === 'high' || risk === 'medium')) {
    for (const re of SHELL_INTENT) {
      if (re.test(content)) {
        flags.push('dangerous_command');
        break;
      }
    }
  }

  // sensitive_path_write: SSH key or similar paths present
  if (!flags.includes('sensitive_path_write') &&
      /~\/\.ssh\/id_(?:rsa|ed25519|ecdsa)|\/etc\/(?:passwd|shadow)|\/root\/\.ssh/i.test(content)) {
    flags.push('sensitive_path_write');
  }

  // network_access: external URLs alongside injection/exfil flags (runs after all flag detection)
  // Exempt localhost/loopback/private ranges — legitimate internal tool calls
  if (!flags.includes('network_access')) {
    const urls = content.match(/https?:\/\/[^\s'"`)]{8,}/gi) || [];
    const hasExternalUrl = urls.some(u => !/https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)/i.test(u));
    if (hasExternalUrl && (flags.includes('prompt_injection') || flags.includes('data_exfiltration') || flags.includes('indirect_injection') || flags.includes('dangerous_command'))) {
      flags.push('network_access');
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

// Sensitive file read targets — reading these is suspicious even without write intent
const SENSITIVE_READ_PATHS = [/\/etc\/(?:shadow|passwd|sudoers|hosts)/, /\/root\//, /~\/.ssh\//, /\/proc\/[0-9]+\/(?:mem|maps|environ)/];

export function assessBehavior(tool, args) {
  const toolLower = (tool || '').toLowerCase();
  const argsStr = argsToString(args);

  // Shell execution tools — check for dangerous commands and network usage
  if (toolLower === 'exec' || toolLower === 'bash' || toolLower === 'shell' || toolLower === 'run') {
    for (const re of DANGEROUS_CMDS) {
      if (re.test(argsStr)) {
        return { risk: 'high', block: true, reason: 'Dangerous command detected', flags: ['dangerous_command'] };
      }
    }
    // Sensitive path access via shell (read or write)
    const cmdStr = args?.command || args?.cmd || argsStr;
    for (const re of SENSITIVE_READ_PATHS) {
      if (re.test(cmdStr)) {
        return { risk: 'high', block: true, reason: 'Shell access to sensitive path', flags: ['dangerous_command', 'sensitive_path_write'] };
      }
    }
    for (const re of NETWORK_CMDS) {
      if (re.test(argsStr)) {
        return { risk: 'medium', block: false, reason: 'Network tool usage detected', flags: ['network_access'] };
      }
    }
  }

  // curl/wget/nc called as a direct tool (not via bash)
  if (NETWORK_CMDS.some(re => re.test(toolLower))) {
    const urlArg = args?.url || args?.uri || args?.target || argsStr;
    // If piped to shell or targeting dangerous endpoints, escalate
    if (/\|\s*(?:bash|sh|zsh|python|perl|ruby)/i.test(urlArg)) {
      return { risk: 'high', block: true, reason: 'Network fetch piped to shell', flags: ['dangerous_command', 'network_access'] };
    }
    return { risk: 'medium', block: false, reason: 'Network tool usage detected', flags: ['network_access'] };
  }

  // File write to sensitive paths
  if (toolLower.includes('write') || toolLower.includes('file') || toolLower === 'write' || toolLower === 'create') {
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
