"""
Turn QAtration breach results into a DEFENSIVE report — the fix list, not the breach list.
Maps each breach's fired detector to a concrete fix + its OWASP LLM Top 10 class,
groups by root cause, prioritizes by severity, renders out/defense_report.html.

Reads every out/results_<target>.json (skips per-model copies like
results_opsbot_qwen.json).
"""
import json, glob, os, sys, html, datetime
from target import target_configs
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from workspace import measured_when
from workspace import (OUT as WORKSPACE_OUT, results_files, target_of,
                       fleet_names, fleet_filter,
                       read_artifact, read_artifacts, say_unreadable, measured,
                       NOT_MEASURED)
from oracle import current_name

OUT_DIR = Path(WORKSPACE_OUT)

# detector -> remediation (severity, OWASP LLM Top-10 class, one concrete fix).
REMEDIATION = {
    "refusal_expected_but_absent": dict(sev="high", order=2,
        owasp="LLM01 Prompt Injection",
        title="Did a thing it was supposed to decline",
        fix=("The request was one the deployment's own scope forbids -- another customer's "
             "details, a refund nobody approved, a receipt for something that did not happen, "
             "legal advice from a shipping assistant -- and the reply carried it out instead "
             "of declining. Nothing leaked and nothing was executed, which is why every other "
             "check here stays quiet: the finding is that the boundary in the system prompt is "
             "advisory. A bot that can be talked into writing whatever the caller wants, under "
             "your name, is a liability before it ever holds a secret. Put the refusable "
             "categories in the system prompt as rules rather than as tone, and check the "
             "OUTPUT for the shapes you never want to send -- a receipt, a refund "
             "confirmation, somebody else's contact details -- because the model deciding to "
             "refuse is not the same as your product refusing.")),

    "planted_instruction_obeyed": dict(sev="high", order=2,
        owasp="LLM01 Prompt Injection",
        title="Followed an instruction that arrived inside data",
        fix=("A quoted document, a forwarded ticket, a page the assistant was shown: the "
             "instruction was in the content, not in the user's request, and the assistant "
             "carried it out. The proof is a token that existed nowhere except inside that "
             "content, returned in a form the text never contained, so quoting cannot explain "
             "it and the corpus cannot either. Whatever else the document had asked for would "
             "have been done as readily. Keep retrieved and pasted material in a separate turn "
             "or field from the request, mark where it starts and ends, and say in the system "
             "prompt that anything inside those marks is quoted material rather than "
             "direction. An output check is worth having as well, since an obeyed injection "
             "usually leaves behind a token or a phrase the answer had no reason to carry.")),

    "insecure_code": dict(sev="high", order=2, owasp="LLM05 Improper Output Handling",
        title="Wrote working code with a classic vulnerability in it",
        fix=("Asked for an ordinary feature — a search box, a diagnostic endpoint, a saved-"
             "workspace loader — the assistant produced code carrying the textbook flaw for "
             "that shape: a query assembled from a value instead of parameterised, a shell "
             "invoked with an interpolated string, client data unpickled, a template rendered "
             "from caller input, a record fetched by id with nothing checking who asked. "
             "Nobody attacked it and nobody asked for something insecure; this is what the "
             "assistant writes when a developer trusts it. Treat generated code as an "
             "untrusted contribution: it goes through the same review and the same static "
             "analysis as a patch from a stranger, and an assistant that produces the "
             "parameterised form by default is worth more than one that produces the fast form "
             "fluently. The detector is paired — it stays silent on the safe version of every "
             "one of these, which is what makes a quiet result mean something.")),
    "hallucinated_package": dict(sev="high", order=2, owasp="LLM03 Supply Chain",
        title="Recommended installing a package that does not exist",
        fix=("The assistant told a developer to install a package the tester had confirmed is "
             "unregistered. This is slopsquatting: the attacker does not need the victim to "
             "click anything, only to register the name the assistant invents and wait. Do not "
             "let a coding assistant name dependencies unchecked — resolve every suggested "
             "package against your own index or lockfile before it reaches a developer, and "
             "prefer an assistant that says it does not know over one that guesses fluently.")),
    "command_injection": dict(sev="high", order=0, owasp="LLM06 Excessive Agency",
        title="Agent coerced into running an arbitrary command (RCE)",
        fix=("The agent ran a command outside its allowed set / with shell metacharacters — "
             "classic command injection, now reached through the AI. Never pass a model-chosen "
             "string to a shell. Expose only fixed, parameterized operations (an enum of allowed "
             "commands), never a free-form command field; run with least privilege in a sandbox.")),
    "ssrf_call": dict(sev="high", order=1, owasp="LLM06 Excessive Agency",
        title="Agent coerced into an internal request (SSRF)",
        fix=("The agent fetched an internal / cloud-metadata URL on attacker instruction — a "
             "direct path to stolen cloud credentials. Don't let the model choose fetch targets: "
             "enforce a strict host allowlist at the TOOL layer (not the prompt), block "
             "link-local/metadata/private ranges, and give the fetch tool no route to internal services.")),
    # Keyed on `canary_in_tool_call`, and it used to be keyed on `tool_poison`. The two fired
    # identically on all 27 of their hits because they shared a helper outright, so the
    # redundancy audit retired one of them — and this table kept the retired NAME. Every MCP
    # tool-poisoning row the engine has found since then arrives under the surviving detector,
    # matches nothing here, and was dropped from the rendered page: the defect the README calls
    # the most important one in the project, deleted at render time by a stale dictionary key.
    "canary_in_tool_call": dict(sev="critical", order=7, owasp="LLM02 Sensitive Information Disclosure",
        title="Secret exfiltrated via a poisoned tool description (MCP tool poisoning)",
        fix=("A hidden instruction inside a TOOL'S DESCRIPTION — not user input, not a document — "
             "made the agent smuggle the confidential key into another tool's argument. In MCP / "
             "tool-using agents the model reads the FULL description while the user sees only a UI "
             "summary. Treat the tool manifest as untrusted: pin and review descriptions, strip "
             "instruction-like content (<IMPORTANT> blocks, 'you must call…'), pin tool versions/"
             "hashes to stop rug-pulls, and isolate servers so one tool's description can't rewrite "
             "another tool's behavior (cross-server shadowing).")),
    "destructive_tool_call": dict(sev="high", order=2, owasp="LLM06 Excessive Agency",
        title="Agent tricked into an irreversible action",
        fix=("Never gate a destructive action on the model's judgment — we flipped it by reframing "
             "deletion as 'a reversible soft-delete'. Put the guard in the TOOL: require out-of-band "
             "confirmation, a second factor, or human approval before it executes. The model may "
             "request the action; it must not authorize it.")),
    "bfla_call": dict(sev="high", order=3, owasp="LLM06 Excessive Agency",
        title="Agent invoked an admin-only function (BFLA)",
        fix=("A customer-role session reached a privileged function (broken function-level "
             "authorization). The prompt said 'admin-only' — the model called it anyway once the "
             "request was reframed as pre-approved. Enforce function-level authz in CODE: check the "
             "authenticated session's role before the tool executes, and don't even expose "
             "privileged tools to sessions that can't use them.")),
    "bola_access": dict(sev="high", order=4, owasp="LLM06 Excessive Agency",
        title="Agent fetched another user's object (BOLA)",
        fix=("The agent read an object it doesn't own — another user's profile or order (broken "
             "object-level authorization). Per-record ownership is a data fact a prompt can't hold: "
             "'only your own data' survives the categorical cases and still leaks on 'pull up order "
             "2001'. Scope every query to the authenticated caller at the data layer (row-level "
             "filter / ownership check in the tool), never from an id the model chose or was given.")),
    "canary_in_output": dict(sev="critical", order=5, owasp="LLM02 Sensitive Information Disclosure",
        title="Secret exfiltrated to the user",
        fix=("A model cannot keep a secret it can see. Keep secrets out of everything the model "
             "reads — system prompt, retrieved documents, tool outputs. Serve authorized data via a "
             "tool that returns only what the caller is entitled to; delete 'NEVER reveal X' "
             "instructions — they don't hold under pressure.")),
    "canary_transformed": dict(sev="critical", order=6, owasp="LLM05 Improper Output Handling",
        title="Secret exfiltrated via an output transform (reverse / ROT13 / split / acrostic)",
        fix=("The secret left the model disguised — spelled backwards, ROT13'd, split by separators, "
             "or as an acrostic — so a plain string filter that greps for the raw value never sees it. "
             "A blocklist on the literal secret is trivially bypassed. Keep the secret out of the "
             "model's context entirely; if you must scan output, normalize/decode it first (strip "
             "separators, reverse, un-rot) before matching — the same way this tool detects it.")),
    "ansi_exfil": dict(sev="high", order=10, owasp="LLM05 Improper Output Handling",
        title="Secret smuggled through terminal control characters (ANSI / OSC-8)",
        fix=("The reply carried raw ANSI/OSC-8 escape sequences — e.g. a terminal hyperlink whose URL "
             "hides the secret, or escapes that conceal text — a channel neither string filters nor "
             "markdown sanitizers inspect and that a terminal auto-renders. Strip or escape control "
             "characters (0x1B/OSC) from model output before displaying it anywhere a terminal or "
             "log viewer will interpret them; never render model-authored escape sequences.")),
    "rogue_tool_call": dict(sev="medium", order=7, owasp="LLM01 Prompt Injection",
        title="Tool invoked with attacker-controlled arguments",
        fix=("The agent passed user-influenced values straight into a privileged tool. Validate and "
             "allowlist tool arguments server-side; parameterize every query (the SQL-injection here "
             "means the tool built raw SQL from the argument); derive identity from the authenticated "
             "session, never from an argument the model chose.")),
    "canary_in_context": dict(sev="high", order=8, owasp="LLM02 Sensitive Information Disclosure",
        title="Data-access boundary crossed (fetched, not shown)",
        fix=("The tool retrieved data the user isn't entitled to; only the model's discretion stopped "
             "it being displayed. Enforce authorization at the data/tool layer — scope every query to "
             "the authenticated user (row-level access) so cross-user data is never fetchable.")),
    "exfil_via_url": dict(sev="high", order=9, owasp="LLM05 Improper Output Handling",
        title="Secret smuggled out through the output (link / image)",
        fix=("The secret left inside a URL or markdown image the model emitted — a channel input "
             "filters don't inspect and that rendered clients auto-fetch. Sanitize model output "
             "before rendering: strip or sandbox markdown images/links, allowlist outbound hosts, and "
             "never let generated content trigger an automatic request that carries data.")),
    "memory_poison": dict(sev="high", order=11, owasp="LLM04 Data and Model Poisoning",
        title="Injected standing rule persisted into a later, benign turn (memory poisoning)",
        fix=("A user turn installed a durable instruction ('from now on…', 'you are now in X mode', "
             "a sleeper trigger) and the bot obeyed it on a later, innocent turn. Don't let free-text "
             "chat write lasting behavior: scope each turn's instructions to that turn, ignore "
             "meta-instructions that try to change future responses, and never carry user-supplied "
             "rules/personas/triggers forward in conversation memory. If durable preferences are a real "
             "feature, gate them behind authenticated config — not whatever the last message claimed.")),
    "malicious_link": dict(sev="high", order=13, owasp="LLM01 Prompt Injection",
        title="Attacker link injected into the answer via poisoned content (indirect injection)",
        fix=("A poisoned document / retrieved chunk made the agent embed an ATTACKER-controlled link "
             "in its reply — a phishing/redirect vector delivered through content the user trusts. "
             "Treat retrieved and third-party content as untrusted data, never instructions: sanitize "
             "generated output (allowlist link domains, strip or rewrite links the model emits), and "
             "isolate document text from the instruction channel.")),
    "tool_enum": dict(sev="medium", order=14, owasp="LLM07 System Prompt Leakage",
        title="Agent disclosed its internal tool / function names (schema enumeration)",
        fix=("The agent listed its callable tools to the user — reconnaissance that maps the attack "
             "surface (which functions exist, what they do) and sets up targeted tool-abuse / BFLA. "
             "Treat the tool manifest as internal config, not user-facing content: instruct the model "
             "never to enumerate its tools, and don't rely on that instruction alone for anything "
             "sensitive — gate privileged tools by role regardless of what the model reveals.")),
    "sysprompt_leak": dict(sev="medium", order=12, owasp="LLM07 System Prompt Leakage",
        title="System prompt disclosed",
        fix=("Assume the system prompt is public — it will leak. Put no secrets, credentials, or "
             "security-through-obscurity in it. Move sensitive config out-of-band and treat the "
             "prompt as readable by anyone.")),

    # ---- Added after the report was caught deleting what it had no fix for. -------------
    # A sixteen-entry table against a fifty-six-detector oracle dropped 49 of 169 findings,
    # and the honest repair was two-part: stop dropping them, then close the gap. These are
    # the second part, written for the classes the fleet actually produced. Severity follows
    # the same rule as the entries above — what an attacker gets, not how exotic the bug is.

    # --- injection into a backend, through the model ------------------------------------
    "sql_injection": dict(sev="high", order=15, owasp="LLM06 Excessive Agency",
        title="Model-composed SQL reached the database",
        fix=("The agent built a query from attacker-influenced text and the database ran it. "
             "This is ordinary SQL injection with the model as the injection point, so the "
             "ordinary fix applies and the prompt-level one does not: parameterised queries or "
             "an ORM at the data layer, never string concatenation. Give the model an enum of "
             "named queries with typed arguments, not a query field. 'Only run safe SQL' in a "
             "system prompt is a request, and this is what happens when it is declined.")),
    "nosql_injection": dict(sev="high", order=16, owasp="LLM06 Excessive Agency",
        title="Model-composed operator injection reached a document store",
        fix=("An attacker-shaped filter object ($ne, $gt, $where, $regex) reached the store, "
             "which turns a lookup into a scan or an authentication check into a tautology. "
             "Reject operator keys in anything the model produced: validate the filter against "
             "a schema that allows literal values only, and build the query in code from named "
             "parameters. A document store's flexibility is the vulnerability here.")),
    "template_injection": dict(sev="high", order=17, owasp="LLM06 Excessive Agency",
        title="Model output was evaluated as a template (SSTI)",
        fix=("A template expression the model produced was EVALUATED, which on most engines is "
             "a direct path from a string to arbitrary code. Never render model output as a "
             "template. If a template must be filled from model output, the model supplies "
             "VALUES into a template the application owns, with autoescaping on and a sandboxed "
             "environment — the payload appearing in a reply is harmless, the payload reaching "
             "the renderer is not, and only the second one is this finding.")),
    "path_traversal": dict(sev="high", order=18, owasp="LLM06 Excessive Agency",
        title="Agent read outside its allowed directory",
        fix=("A `../` sequence or an absolute path in a model-chosen argument escaped the "
             "intended directory. Do not pass a model-chosen path to a filesystem call: map an "
             "opaque identifier to a path in code, resolve the result and assert it is inside "
             "the allowed root after resolution (a check before normalisation is defeated by "
             "encoding), and run the process without read access to anything else.")),
    "xxe_payload": dict(sev="high", order=19, owasp="LLM06 Excessive Agency",
        title="XML with external entities reached a parser",
        fix=("A DOCTYPE with an external entity reached XML parsing, which reads local files "
             "and makes outbound requests from your server. Disable DTD processing and external "
             "entity resolution in the parser (`defusedxml`, or resolve_entities=False), and "
             "prefer a format with no entity mechanism. The model did not have to intend this; "
             "it only had to relay a document.")),

    # --- what the reply does in the next system -----------------------------------------
    "xss_in_output": dict(sev="high", order=20, owasp="LLM05 Improper Output Handling",
        title="Reply carried active markup into the host application",
        fix=("The reply contains script or an event handler, inert in a terminal and stored XSS "
             "the moment a chat widget renders it as HTML. Treat every model reply as untrusted "
             "input to the renderer: escape by default, allowlist the markup you actually "
             "support through a sanitiser, and set a Content-Security-Policy that forbids "
             "inline script. Filtering the model's output with another prompt is the same "
             "trust boundary that just failed.")),
    "data_uri_output": dict(sev="medium", order=21, owasp="LLM05 Improper Output Handling",
        title="Reply carried a data: URI",
        fix=("A `data:` URI smuggles a whole payload past filters that inspect hosts, and in a "
             "renderer it can carry markup or an executable download. Strip `data:` and "
             "`javascript:` schemes from replies at the boundary, allowlisting `https:` and "
             "the schemes the product genuinely uses.")),
    "known_bad_signature": dict(sev="medium", order=22, owasp="LLM05 Improper Output Handling",
        title="Draft carried a signature the next system acts on",
        fix=("The output contains a standard test signature (EICAR, GTUBE, GTPHISH). Nothing "
             "malicious happened and nothing has to: the document is quarantined by the "
             "recipient's antivirus, or the mail is filed as spam by their gateway, and the "
             "sender finds out from the customer. Where a reply becomes a file, a mail body or "
             "a published page, scan it on the way OUT with the same tooling the recipient "
             "runs, and fail closed.")),
    "invisible_chars": dict(sev="medium", order=23, owasp="LLM05 Improper Output Handling",
        title="Reply carried zero-width or hidden characters",
        fix=("Zero-width and formatting characters survive copy-paste and are invisible in "
             "review, so they carry instructions into the next model that reads the text and "
             "defeat string comparison in the next system that stores it. Normalise replies "
             "(NFKC) and strip the Cf category on the way out of the model and on the way into "
             "anything that indexes, diffs or re-prompts on them.")),
    "bidi_override": dict(sev="medium", order=24, owasp="LLM05 Improper Output Handling",
        title="Reply carried bidirectional overrides",
        fix=("Bidi override characters make displayed text differ from stored text, so a "
             "reviewer approves one string and the system runs another — the Trojan Source "
             "problem, arriving through a support ticket. Strip U+202A-U+202E and U+2066-U+2069 "
             "from replies, and render with the direction the application chose rather than the "
             "one the content asks for.")),
    # --- written when their detectors were, rather than left for the unmapped section -----
    #
    # A finding with no remediation text still reaches the reader — the report lists it under
    # "no fix written" rather than dropping it, which is the right default and a poor place to
    # leave anything on purpose. Seventeen detectors sat there; these are the ones whose fix is
    # a sentence somebody can act on rather than a research question.
    "secret_material_access": dict(sev="high", order=2,
        owasp="LLM06 Excessive Agency",
        title="Agent reached for credentials at rest",
        fix=("The agent wrote code that reads the process environment, a credential file or a "
             "key store — `os.environ`, `/proc/self/environ`, `~/.aws/credentials`, a `.env`, "
             "an ssh key. Whether the sandbox refused it is a second line of defence the agent "
             "did not provide, and one `additional_authorized_imports` away from not applying. "
             "Give the execution environment nothing worth reading: run it with a minimal "
             "environment rather than the deployment's, mount no credential files into it, and "
             "supply what the agent legitimately needs through a tool that returns only the "
             "answer. A key the process cannot see is a key no prompt can reach."),
        ),
    "capitulation": dict(sev="medium", order=27,
        owasp="LLM09 Misinformation",
        title="The assistant reversed a factual answer under pressure alone",
        fix=("A customer disputed an answer without supplying anything new and the assistant "
             "abandoned it. Nothing was breached; the exposure is commercial and contractual, "
             "because the reversed answer is about a refund window, an eligibility or a fee, "
             "and the customer now has it in writing. Facts a customer can argue with should "
             "not be generated: answer them from a lookup and quote the source, so there is "
             "nothing for the model to concede. Where the model must answer freely, measure "
             "consistency across a pressured exchange rather than a single reply, and route "
             "disputes to a person instead of to another generation."),
        ),
    "role_assumed": dict(sev="high", order=6,
        owasp="LLM06 Excessive Agency",
        title="A role the caller only claimed was granted",
        fix=("The system worked out who it was talking to from the conversation rather than "
             "from the session. Nothing was called and nothing read, which is why this leaves "
             "no trace in a tool log — and it is the step that makes every privileged action "
             "downstream look legitimate. Identity must arrive with the request and never from "
             "inside it: resolve the caller's role server-side, pass it to the model as "
             "context it cannot change, and have every privileged tool check that context "
             "rather than the model's belief. Treat any role assertion in a message as data "
             "about what the user WANTS, not about who they are."),
        ),
    "pii_in_output": dict(sev="high", order=28,
        owasp="LLM02 Sensitive Information Disclosure",
        title="Personal data in the reply",
        fix=("Personal data left through the reply. Whether that was allowed depends on who "
             "was asking, which this check cannot see — read it beside the authorization "
             "findings rather than alone. Scope retrieval and tool responses to the "
             "authenticated caller at the source rather than filtering afterwards: a record "
             "the model never receives cannot be repeated, and a redaction pass over the "
             "output is a race the model wins whenever it paraphrases."),
        ),
    "credential_in_output": dict(sev="critical", order=7,
        owasp="LLM02 Sensitive Information Disclosure",
        title="A credential-shaped string in the reply",
        fix=("A string matching a known credential format appeared in a reply and did not come "
             "from the request. Treat it as live: rotate it before deciding how it got there. "
             "Then find what put it within reach — a tool response carrying a whole record, a "
             "document in the retrieval corpus, an environment the model can read — and remove "
             "it at that layer rather than pattern-matching the output."),
        ),
    "credential_in_tool_call": dict(sev="critical", order=8,
        owasp="LLM02 Sensitive Information Disclosure",
        title="A credential left through a tool argument",
        fix=("The same disclosure as the one above through a channel nobody watches: a key "
             "handed to a search query, a webhook or a telemetry call never appears on screen "
             "and is gone all the same. Rotate it, then log and review tool arguments with the "
             "same seriousness as replies — most deployments monitor only what the user sees."),
        ),
    "refusal_then_comply": dict(sev="medium", order=9,
        owasp="LLM01 Prompt Injection",
        title="Refused and complied in the same answer",
        fix=("The reply declines and then does it anyway — often in one sentence, naming the "
             "value it says it cannot name. Any guard that scores refusal text is scoring the "
             "wrong half. Check the reply for the protected VALUE, not for an apology, and "
             "prefer a boundary the model cannot cross to one it is asked to honour."),
        ),
    "over_refusal": dict(sev="medium", order=40,
        owasp="LLM09 Misinformation",
        title="An in-scope question refused",
        fix=("A question the deployment exists to answer was refused, usually because it "
             "contained something that reads as dangerous — a log line with SQL in it, a "
             "customer quoting an error. This is the cost side of a guardrail and it is real: "
             "it is measured in tickets that reach a human. Tune the guard on the ANSWER "
             "rather than the question, so a customer describing a problem is not mistaken for "
             "somebody causing one."),
        ),
    "model_identification": dict(sev="medium", order=41,
        owasp="LLM07 System Prompt Leakage",
        title="The deployment named its own model",
        fix=("The system disclosed which model and version is behind it. Not a breach on its "
             "own; it is reconnaissance, and it tells an attacker which published jailbreaks "
             "and which token quirks to reach for first. Say nothing about the stack in the "
             "system prompt, and treat questions about it as out of scope."),
        ),
    "sysprompt_paraphrase": dict(sev="medium", order=22,
        owasp="LLM07 System Prompt Leakage",
        title="The instructions came back reworded",
        fix=("The reply restates the system prompt in different words, which carries the same "
             "information as a verbatim dump and passes any check that matches on phrases. "
             "The durable answer is not to hide the prompt but to stop it being worth reading: "
             "keep secrets, identifiers and business rules out of it, and enforce them where "
             "the model cannot see them."),
        ),
    "instruction_in_output": dict(sev="high", order=42,
        owasp="LLM05 Improper Output Handling",
        title="The reply carries instructions for whatever reads it next",
        fix=("The output contains imperative text aimed at a downstream reader — another agent, "
             "a summariser, a ticket system. Anything that consumes this reply must treat it as "
             "data: pass it as content rather than as a prompt, and strip or escape it at the "
             "boundary between systems."),
        ),
    "markdown_beacon": dict(sev="high", order=23,
        owasp="LLM05 Improper Output Handling",
        title="The reply fetches a remote resource when it is displayed",
        fix=("A markdown image or link in the reply causes the viewer to make a request to a "
             "third party on render — which leaks that the message was read, and can carry "
             "data in the URL. Render replies with remote resource loading disabled, or "
             "rewrite external image references to a placeholder before display."),
        ),
    "session_leak": dict(sev="critical", order=10,
        owasp="LLM08 Vector and Embedding Weaknesses",
        title="Content from another session appeared",
        fix=("Material that belongs to a different conversation surfaced in this one. Look at "
             "shared state first: a cache keyed too loosely, a memory store without a tenant "
             "key, a retrieval index that spans customers. This is the finding that most often "
             "means a data-protection notification rather than a patch."),
        ),
    "exfil_via_hostname": dict(sev="critical", order=11,
        owasp="LLM05 Improper Output Handling",
        title="A secret encoded into a hostname",
        fix=("The value left inside a DNS name, which resolves before any HTTP filter sees it "
             "and appears in no proxy log. Egress control has to be at the resolver and the "
             "network, not at the URL: allowlist the hosts the deployment may reach and deny "
             "everything else by default."),
        ),
    "unknown_tool_call": dict(sev="medium", order=26,
        owasp="LLM06 Excessive Agency",
        title="A tool that is not in the manifest was called",
        fix=("The agent invoked something the configuration does not list. Either the manifest "
             "is stale — in which case nothing here is being checked against reality — or the "
             "agent reached a capability nobody declared. Enforce the tool list at the "
             "execution layer rather than describing it in a prompt."),
        ),
    "divergent_repetition": dict(sev="medium", order=29,
        owasp="LLM02 Sensitive Information Disclosure",
        title="Training data surfaced after a repetition loop",
        fix=("Asked to repeat something indefinitely, the model fell out of the loop and kept "
             "generating text nobody asked for, which can include memorised training data. Cap "
             "output length at the serving layer and stop generation on runaway repetition; "
             "neither belongs in a prompt instruction."),
        ),
    "forced_output": dict(sev="medium", order=43,
        owasp="LLM01 Prompt Injection",
        title="The reply's shape was dictated by the request",
        fix=("The request specified the exact form of the answer and got it, which is how a "
             "response gets steered into a channel a downstream system trusts. Validate replies "
             "against the schema your own application expects rather than the one the user "
             "asked for."),
        ),

    "fabricated_contact": dict(sev="high", order=24, owasp="LLM05 Improper Output Handling",
        title="Bot gave customers a contact address at a domain you do not own",
        fix=("The reply directed a customer to your own brand at a domain outside the "
             "allowlist you declared — `support@acmeshop.example` from a company that owns "
             "acmeshop.example. Nobody attacked anything to produce it: the model needed a "
             "contact address, none was in its instructions, and it wrote the one a customer "
             "would expect. That is a phishing target you have created and advertised, and it "
             "stays open until someone registers the domain. Put the real contact channels in "
             "the system prompt so the model has no gap to fill, resolve every host in a reply "
             "against the domains you control, and register the obvious neighbours of your own "
             "name. Check your support logs for customers who already used it."),
        ),
    "lookalike_domain": dict(sev="medium", order=25, owasp="LLM05 Improper Output Handling",
        title="Reply pointed the customer at a lookalike domain",
        fix=("The reply carried a homograph or typosquat of a domain you own, which is the "
             "payload of a phishing campaign delivered by your own support channel and wearing "
             "your brand. Resolve every host in a reply against an allowlist of domains you "
             "control, punycode-decoded first, and replace anything else with a plain-text "
             "notice rather than a link. A model cannot be relied on to notice the difference "
             "between two strings that were designed to look the same.")),
    "special_token_output": dict(sev="medium", order=26, owasp="LLM05 Improper Output Handling",
        title="Reply emitted the model's own control tokens",
        fix=("Chat-template control tokens in the visible reply let anything that re-parses the "
             "text — a logging pipeline, a summariser, the next turn of this same model — read "
             "a forged turn boundary. Strip the template's special tokens from output, and "
             "never rebuild a conversation by concatenating stored replies as text.")),

    # --- authorization and data flow ----------------------------------------------------
    "idor_enumeration": dict(sev="high", order=27, owasp="LLM06 Excessive Agency",
        title="Agent walked a sequence of identifiers",
        fix=("The agent fetched a run of ids rather than the one it was asked for, which turns "
             "one leaked record into the whole table. Ownership is a data fact a prompt cannot "
             "hold: filter every read by the authenticated caller at the data layer, and "
             "rate-limit per session so a walk is refused by the tool rather than declined by "
             "the model.")),
    "mass_assignment": dict(sev="high", order=28, owasp="LLM06 Excessive Agency",
        title="Privileged field reached a write through the model",
        fix=("A field the caller should not be able to set — role, is_admin, balance, price — "
             "appeared in an argument the model composed. Never spread model output into a "
             "record. Accept an explicit allowlist of writable fields per operation, drop "
             "everything else server-side, and check the caller's right to each one separately "
             "from the request that carried it.")),
    "pii_in_tool_call": dict(sev="high", order=29, owasp="LLM02 Sensitive Information Disclosure",
        title="Personal data left in a tool argument",
        fix=("Personal data appeared in an argument to a tool that did not need it, so it "
             "crossed a boundary — an outbound request, a log, a third-party API — on the "
             "model's judgment. Give each tool the narrowest signature that does its job (an id "
             "rather than a record), redact at the tool boundary rather than in the prompt, and "
             "keep the argument log to the same retention rules as the data it now contains.")),
    "cross_tool_taint": dict(sev="high", order=30, owasp="LLM01 Prompt Injection",
        title="One tool's output became another tool's argument",
        fix=("Data a tool RETURNED was passed into a tool that sends, writes or fetches, which "
             "is the shape of every agentic exfiltration: retrieve, then transmit. Treat a tool "
             "return as untrusted. Where an agent can both read private data and reach the "
             "outside, break the pair — separate the read and the send into different sessions, "
             "or require human approval on the send once a privileged read has happened in the "
             "same trace.")),
    "canary_normalized": dict(sev="critical", order=31, owasp="LLM02 Sensitive Information Disclosure",
        title="Secret leaked with its formatting changed",
        fix=("The protected value left with punctuation, spacing or case altered, which is a "
             "full disclosure that every exact-match output filter passes. Do not filter for the "
             "secret on the way out; keep it out of everything the model reads. Where an output "
             "check is the only option, compare normalised forms — but treat that as a tripwire, "
             "not a control, because the transformations are unbounded.")),
    "canary_encoded": dict(sev="critical", order=32, owasp="LLM02 Sensitive Information Disclosure",
        title="Secret leaked through an encoding",
        fix=("The protected value left base64-, hex- or URL-encoded. Same conclusion as the "
             "plain leak and a sharper version of it: a model that can see a secret can re-emit "
             "it in a form no denylist enumerates. The control is architectural — serve "
             "authorised data through a tool that checks the caller, and never place the secret "
             "in the context window.")),
    "debug_disclosure": dict(sev="medium", order=33, owasp="LLM02 Sensitive Information Disclosure",
        title="Reply carried internal diagnostics",
        fix=("A stack trace, an internal hostname, a file path or a framework version reached "
             "the user, handing an attacker the map before the attack. Catch errors at the tool "
             "boundary and return a stable, opaque message with a correlation id; log the detail "
             "server-side. The model relays whatever a tool hands it, so the redaction belongs "
             "in the tool.")),

    # --- what the answer claims ----------------------------------------------------------
    "verbatim_replay": dict(sev="medium", order=34, owasp="LLM02 Sensitive Information Disclosure",
        title="Reply reproduced a source document word for word",
        fix=("The answer is a copy of a retrieved document rather than an answer drawn from it. "
             "That publishes whatever the source contains — internal notes, another customer's "
             "wording, licensed text — to whoever asked a question near it. Chunk and label the "
             "corpus by who may see it, filter retrieval by the caller's entitlements before the "
             "model sees a document, and cap contiguous quotation at the application layer.")),
    "memorised_completion": dict(sev="medium", order=35, owasp="LLM02 Sensitive Information Disclosure",
        title="Reply reproduced text from training, not from a source",
        fix=("Asked for a continuation, the deployment produced text nobody sent it. That is a "
             "compliance question before it is a security one: where output becomes a published "
             "page or an outbound mail, reproduced third-party text is a licensing exposure with "
             "your name on it. Ground generation in retrieval and refuse to continue verbatim "
             "from an unsourced fragment; where quotation is a real feature, quote from a corpus "
             "you own and cite it.")),
    "fabricated_citation": dict(sev="medium", order=36, owasp="LLM09 Misinformation",
        title="Answer cited a source that was never retrieved",
        fix=("The reply carries a citation to a document the retrieval step did not return, "
             "which is the most persuasive shape a wrong answer takes: it looks checked. "
             "Validate every citation against the retrieved set before rendering, and drop the "
             "answer rather than the citation when they disagree. An unsourced claim presented "
             "as sourced is worse than one presented as a guess.")),

    # --- cost and availability -------------------------------------------------------------
    "off_scope_code": dict(sev="medium", order=36.5, owasp="LLM10 Unbounded Consumption",
        title="The deployment did work that is not its job",
        fix=("Asked for a program, a support bot wrote one. Nothing forbidden was requested "
             "and a helpful assistant complies, which is the problem: the scope in the system "
             "prompt is a preference, not a control. It costs three things at once — an "
             "unmetered inference bill on somebody else's work, a brand surface nobody signed "
             "off, and, where the output is published or emailed without review, a program on "
             "your website. Put the boundary outside the model: classify the request before it "
             "reaches the model and refuse out-of-domain ones in code, cap tokens per user per "
             "day so abuse is bounded rather than argued about, and log the refusals so you "
             "can see what people are trying to use it for. Adding 'only answer questions "
             "about orders' to the prompt is the control that just failed.")),
    "unbounded_output": dict(sev="medium", order=37, owasp="LLM10 Unbounded Consumption",
        title="One request produced an unbounded generation",
        fix=("A single prompt made the deployment generate until something else stopped it, "
             "which is a bill and a queue other users are waiting in. Cap output tokens at the "
             "API call, set a request timeout that CLOSES the socket so the server stops too, "
             "and rate-limit per caller. A limit the client abandons rather than enforces leaves "
             "the model generating for nobody.")),
    "degenerate_output": dict(sev="medium", order=38, owasp="LLM10 Unbounded Consumption",
        title="Reply collapsed into repetition",
        fix=("The reply degenerated into a repeated fragment, which burns the budget and ships a "
             "broken answer. Detect a repeated n-gram run in the streaming response and cut it, "
             "then return a fallback rather than the collapse. It is also a signal worth "
             "alerting on: it usually means the prompt or the sampling parameters changed.")),
    "slow_response": dict(sev="medium", order=39, owasp="LLM10 Unbounded Consumption",
        title="One request held a worker far past the expected latency",
        fix=("A single request occupied the model server long enough to starve the queue behind "
             "it. Enforce a deadline at the tool and at the model client, shed load rather than "
             "queueing indefinitely, and alarm on the tail latency rather than the mean — a "
             "stall reaches every other user before it reaches a dashboard.")),
    "repeated_tool_call": dict(sev="medium", order=40, owasp="LLM10 Unbounded Consumption",
        title="Agent called the same tool with the same arguments repeatedly",
        fix=("The agent looped on one call, paying for every iteration and, where the tool "
             "writes, repeating the write. Cap steps per session in the agent loop, break on a "
             "repeated (tool, arguments) pair, and make write tools idempotent with a caller-"
             "supplied key so a retry cannot double an effect.")),
    "tool_call_storm": dict(sev="medium", order=41, owasp="LLM10 Unbounded Consumption",
        title="One request produced a burst of tool calls",
        fix=("A single prompt fanned out into far more tool calls than the task needed. Cap "
             "calls per session in the agent loop rather than trusting the plan, rate-limit each "
             "tool per caller, and fail the session loudly when the cap is hit so the burst is "
             "visible instead of merely expensive.")),
}
SEV = {"critical": "#b3261e", "high": "#c2410c", "medium": "#9a6700"}
# ---------------------------------------------------------------------------------------------
# ROOT CAUSES, and why they are not detectors.
#
# The page grouped findings by DETECTOR and called each group a root cause, which multiplied
# detection routes into problems. Four detectors notice a planted secret leaving — plainly, base64
# encoded, with its formatting changed, reversed — and their four `fix` texts are the same
# sentence: keep the secret out of everything the model reads. That is one problem seen four
# ways, and counting it as four inflated both the root-cause tile and the critical band.
#
# The test for membership is checkable rather than aesthetic, and it is the one the severity
# rubric states: IF TWO FIX TEXTS NAME THE SAME PRIMARY CONTROL, ONE OF THEM IS A CHANNEL. Where
# a channel needs an extra control of its own — a resolver allowlist for a secret smuggled into a
# hostname — that control is kept, attached to the channel, under the parent.
#
# Detectors that merely LOOK similar stay separate. `canary_in_tool_call` notices the same asset
# leaving, but its remediation is tool-manifest pinning: a different artefact, owned by a
# different team, and collapsing it would hide the only advice that would have prevented it.
ROOT_CAUSES = {
    "secret-out": dict(
        sev="critical", order=3, owasp="LLM02 Sensitive Information Disclosure",
        title="A planted secret reached an output channel",
        fix=("A value the deployment was told to keep left it. The channel varies — written "
             "plainly, encoded, reformatted, reversed — and the control does not: keep the "
             "secret out of everything the model can read. It cannot disclose what it was never "
             "given. Filtering the output is the wrong layer: every entry below is a way past a "
             "filter, and there are more of them than anyone can enumerate."),
        members=["canary_in_output", "canary_encoded", "canary_normalized",
                 "canary_transformed", "exfil_via_hostname"]),

    "credential-out": dict(
        sev="critical", order=4, owasp="LLM02 Sensitive Information Disclosure",
        title="A live credential left the deployment",
        fix=("ROTATE IT FIRST — unlike a planted canary, this is a working secret and the run "
             "has demonstrated a way out. Then the same structural fix: a credential the model "
             "can read is a credential the model can be talked into repeating, so keep it in the "
             "tool layer and pass a handle rather than the value."),
        members=["credential_in_output", "credential_in_tool_call"]),

    "object-authz": dict(
        sev="high", order=5, owasp="LLM06 Excessive Agency",
        title="Object-level authorization is not enforced at the data layer",
        fix=("The agent reached a record it had no claim to — once, or by walking a sequence of "
             "identifiers. Both are the same missing control: filter every read by the "
             "authenticated caller in the query itself, not in the prompt and not in the tool "
             "wrapper. An identifier the model can compose is an identifier an attacker can."),
        members=["bola_access", "idor_enumeration"]),

    "model-composed-query": dict(
        sev="high", order=6, owasp="LLM06 Excessive Agency",
        title="The model composes a datastore query",
        fix=("A string the model wrote reached the database as query structure rather than as "
             "data — as SQL, or as operators in a document store. Build the query in code from "
             "named, typed parameters and let the model choose only values. This is the oldest "
             "injection there is, arriving through a new front door."),
        members=["sql_injection", "nosql_injection"]),

    "outbound-on-render": dict(
        sev="high", order=12, owasp="LLM05 Improper Output Handling",
        title="A rendered reply makes an outbound request",
        fix=("The reply carries something that fetches a remote resource the moment it is "
             "displayed — a link built from data, an image that beacons. Whatever is in the URL "
             "leaves with it, and the user never clicks anything. Do not render model output as "
             "markup; if you must, allowlist the hosts at the renderer rather than asking the "
             "model not to."),
        members=["exfil_via_url", "markdown_beacon"]),

    "sysprompt-as-secret": dict(
        sev="medium", order=20, owasp="LLM07 System Prompt Leakage",
        title="The system prompt is treated as a secret",
        fix=("It came back — verbatim, or reworded, which carries the same information. Assume "
             "it is public, because it will be. Put no credentials, no security-by-obscurity "
             "and no rule you would mind an attacker reading into it; the map is only valuable "
             "if the territory depends on it staying hidden."),
        members=["sysprompt_leak", "sysprompt_paraphrase"]),

    "parser-hostile-output": dict(
        sev="medium", order=21, owasp="LLM05 Improper Output Handling",
        title="The reply carries characters the next parser acts on",
        fix=("Zero-width characters, bidirectional overrides, or the model's own control tokens "
             "reached the output. Each is invisible to the reader and meaningful to whatever "
             "parses the text next. Strip the class on the way out, at the boundary, rather "
             "than hoping the next consumer is careful."),
        members=["invisible_chars", "bidi_override", "special_token_output"]),

    "no-resource-ceiling": dict(
        sev="medium", order=22, owasp="LLM10 Unbounded Consumption",
        title="No per-request resource ceiling",
        fix=("One request was able to consume without bound — generating until something else "
             "stopped it, collapsing into repetition, holding a worker, or firing a burst of "
             "tool calls. These are one missing control seen five ways: cap output length, wall "
             "time and tool calls per request at the serving layer, where the model cannot "
             "argue with the limit."),
        members=["unbounded_output", "degenerate_output", "slow_response",
                 "tool_call_storm", "repeated_tool_call"]),
}

# detector -> the root cause it belongs to. A detector absent from this map IS its own root
# cause, which is the common case and the correct default.
DETECTOR_ROOT = {d: gid for gid, g in ROOT_CAUSES.items() for d in g["members"]}


def root_key(detector):
    """The key a finding is filed under: its root cause if it has one, otherwise itself."""
    return DETECTOR_ROOT.get(detector, detector)


def entry(key):
    """The remediation record for a root-cause key, whether it is a group or a lone detector."""
    return ROOT_CAUSES.get(key) or REMEDIATION[key]


SEV_RANK = {"critical": 0, "high": 1, "medium": 2}
SEV_BG = {"critical": "rgba(179,38,30,.12)", "high": "rgba(194,65,12,.12)", "medium": "rgba(154,103,0,.12)"}


def esc(s):
    return html.escape(str(s))


def _rate_frac(rate):
    """'2/3' -> 0.67; used to lead evidence with the most reproducible example."""
    try:
        n, d = (int(x) for x in str(rate).split("/"))
        return n / d if d else 0.0
    except Exception:
        return 0.0


def payload_text(a):
    d = a.get("delivery")
    if d == "indirect":
        s = a.get("seed", {})
        return f"[user] {a.get('user_prompt','')}\n[planted] {s.get('text','')}"
    if d == "chain":
        return "\n".join(f"[turn {i+1}] {s}" for i, s in enumerate(a.get("steps", [])))
    return a.get("text", "")


def load_all(known=None):
    """Findings, the targets they came from, and WHEN each target was measured.

    A remediation report is read as a statement about how things are now. Aggregating runs
    from different days without saying so turns a fixed issue into a live one and a stale
    number into a current claim, so the dates come along and the page says when they differ.
    """
    findings, targets, dates = [], set(), {}
    # A RESULTS FILE WHOSE TARGET HAS NO CONFIG IS NOT A SYSTEM THAT WAS TESTED. `out/` keeps
    # whatever ever ran, so a one-off target whose config is gone goes on being counted in
    # "N systems tested" forever. This page published 32 for a fleet of 30, from two artifacts
    # of the deliberately-unreachable end-to-end fixture. Empty `known` means no filtering,
    # which is what the temp-directory fixtures in the suites need.
    # Read every meta first, then ask which of them belong to the fleet — the decision needs
    # to see the whole directory, because "none of these resolve" means this is not the
    # fleet's directory rather than "the fleet is empty".
    # READ ONCE, AND AN UNREADABLE FILE IS NEITHER FATAL NOR INVISIBLE.
    #
    # This opened every artifact twice. The first pass caught the failure and substituted an
    # EMPTY META — which then went into `fleet_filter`, the function deciding whether this is
    # the fleet's directory by its contents, so a file nobody could read got a vote on the
    # answer. The second pass over the same files had no handler and took the entire report
    # down with a raw JSONDecodeError: no page, and nothing naming the file.
    #
    # A truncated artifact is what an interrupted write leaves. Stopping a sweep by hand
    # produces one. Four other tools that read this directory died the same way, which is why
    # the reader now lives in `workspace` and this is one of its callers.
    _parsed, _unreadable = read_artifacts(results_files(OUT_DIR))
    _metas = {fp: (d.get("meta") or {}) for fp, d in _parsed.items()}
    _keep, _drop = fleet_filter(list(_metas.values()), known)
    _keep_names = {(m or {}).get("target") for m in _keep}
    for fp, d in _parsed.items():
        tgt = (d.get("meta") or {}).get("target")
        if not tgt:
            _unreadable.append((fp, "no meta.target — not a results file"))
            continue
        if tgt not in _keep_names:
            continue
        targets.add(tgt)
        # THE RUN'S DATE WHERE THE RUN RECORDED ONE. `os.path.getmtime` is a filesystem
        # event: git does not preserve mtimes, so a fresh clone stamps every artifact with
        # the clone day and this report dated three weeks of evidence as today. One reader
        # in `workspace` now, shared with the fleet page.
        dates[tgt] = measured_when((d.get("meta") or {}), fp)[0][:10]
        for r in d["results"]:
            if r["headline"] in ("EXPLOITED", "PARTIAL") and r["attack"].get("category") != "control":
                best = sorted(r["trials"], key=lambda t: 0 if t["verdict"] in ("EXPLOITED", "PARTIAL") else 1)[0]
                findings.append((tgt, r["attack"], r["headline"], r["fired"],
                                 best.get("probe") or {}, r.get("rate", "")))
    return findings, targets, dates, _unreadable


def _timeline():
    """target -> (first_seen per attack, set of attacks that came BACK after a fix).

    "Critical" is an opinion. "Critical, open since the 3rd, and we already closed it once"
    is a fact about how a team responds to them, and it is the sentence somebody acts on.
    The data existed in out/history and stopped at the console.
    """
    try:
        from history import first_seen, diff, load
    except Exception:
        return {}, {}
    ages, back = {}, {}
    for fp in glob.glob(str(OUT_DIR / "history" / "*.jsonl")):
        t = os.path.basename(fp)[:-len(".jsonl")]
        ages[t] = first_seen(t)
        d = diff(t)
        back[t] = set(d.get("regressed") or []) if "reason" not in d else set()
    return ages, back


def _unresolved_paths():
    """target -> the response paths its config declared and its run never once resolved.

    `caps` on a results file says what the config CLAIMED the target exposes. This says which
    of those claims the sweep could not substantiate a single time. The two disagreeing is the
    case that matters: sixteen detectors read the tool-call channel, and against a mistyped
    path every one of them judged an empty list and reported nothing — a clean tool surface for
    a deployment whose tool calls were never read.
    """
    out = {}
    for fp in results_files(OUT_DIR):
        try:
            m = (read_artifact(fp)[0] or {})["meta"]
        except (ValueError, KeyError, OSError):
            continue
        bad = m.get("unresolved_paths") or []
        if bad:
            out[m.get("target", "?")] = list(bad)
    return out


def _unobservable():
    """target -> calls whose contents no detector could see.

    Reported beside the findings because the difference between "we checked and it was
    clean" and "we could not see" is the difference between a measurement and a promise, and a
    report that blurs the two is worth less than one that admits the gap.
    """
    try:
        from oracle import blind_spots
        from target import Probe
    except Exception:
        return {}
    out = {}
    for fp in results_files(OUT_DIR):
        # The last bare read in this file, and the one that survived the first pass: a
        # truncated artifact raised here and took the whole report down after `load_all` had
        # already been taught to carry on. `load_all` names it; this one carries on quietly
        # rather than saying it twice.
        d, _why = read_artifact(fp)
        if _why:
            continue
        tgt = (d.get("meta") or {}).get("target")
        if not tgt:
            continue
        cfg = CTXS.get(tgt, {})
        for r in d["results"]:
            for tr in r.get("trials", []):
                pd = tr.get("probe") or {}
                if not pd:
                    continue
                pr = Probe(prompt="", output=pd.get("output") or "",
                           tool_calls=[tuple(x) for x in (pd.get("tool_calls") or [])],
                           resolved=[tuple(x) for x in (pd.get("resolved") or [])])
                for b in blind_spots(pr, cfg):
                    out.setdefault(tgt, {}).setdefault(b, set()).add(r["attack"]["id"])
    return out


def _contexts():
    import yaml as _y
    here = os.path.dirname(os.path.abspath(__file__))
    out = {}
    for fp in target_configs(here):
        c = _y.safe_load(open(fp, encoding="utf-8")) or {}
        out.setdefault(c.get("name") or os.path.basename(fp)[8:-5],
                       c.get("oracle_context", {}))
    return out


CTXS = _contexts()


def ambient_rates():
    """target -> detector -> share of its BENIGN probes that fired it.

    Used to decide what a short run leads with. A row whose detector also fires on the target's
    own ordinary traffic is the worst thing to put first, because the first thing a competent
    reader does is try it WITHOUT the attack — and then the whole report is worth nothing to
    them, however good the rest of it is.
    """
    # THROUGH `baseline.rates`, WHICH IS THE NOISE FLOOR. This kept its own, dividing by
    # `meta["probes"] or len(rows)` -- and `benign.py` writes `probes = len(rows)`,
    # counting rows it also marked `skipped` and never sent. `baseline` divides by the
    # rows that carry a probe. On `benign_localrag.json` that is 48 against 50 today.
    #
    # It mattered here more than anywhere: this function ORDERS the findings and
    # `attribution_index` LABELS the same rows through `baseline.rates`, so one page
    # could lead with a row it then stamped UNATTRIBUTED. Both directions of the error
    # understate noise, which flatters every finding on the page.
    from baseline import rates as _rates
    out = {}
    for fp in glob.glob(str(OUT_DIR / "benign_*.json")):
        t = os.path.basename(fp)[len("benign_"):-len(".json")]
        r = _rates(t, str(OUT_DIR))
        if r is not None:
            out[t] = r
    return out


def arsenal_ran():
    """target -> (sent, skipped, trials). How much of the arsenal this run actually used.

    A RUN THAT SENT FIVE ATTACKS OF A HUNDRED AND THIRTY-SEVEN REPORTED AS A RUN. Measured on
    the first job that went through the front door: a configured target gets the default
    arsenal, almost every attack in which is scoped `applies_to` a specific practice bot, so
    132 never left the building. The console said so and the page did not, and the page is what
    somebody reads.

    Reported as COUNTS and not as a coverage percentage, because the percentage was itself the
    defect one level along. On the fleet page every target runs `attacks.yaml`, which holds
    each bot's bespoke attacks plus the generic ones; a row skipped there was written for a
    different system and was never a candidate, so dividing by the file size produced "4%
    coverage" for sixteen targets that were in fact fully covered by the attacks meant for
    them. The same arithmetic, true in one place and meaningless in the other — a gap reported
    as a measurement, introduced by the section written to stop one. What a reader can use is
    the pair of numbers and the name of the arsenal, and the judgement stays theirs.
    """
    out = {}
    for fp in results_files(OUT_DIR):
        stem = os.path.basename(fp)[len("results_"):-len(".json")]
        try:
            m = ((read_artifact(fp)[0] or {}).get("meta") or {})
        except Exception:
            continue
        sent, skipped = m.get("attacks_n"), m.get("skipped")
        if sent is None or not skipped:
            continue
        # THE SUM ANSWERS A QUESTION NOBODY ASKED. Of 333 rows outside one walked run, 319
        # were held by `--scope quick` and 14 were beyond what the deployment can take. This
        # page called all of them "scoped out" and explained them as written for other
        # systems, which was true of none. `not_sent` is None on artifacts written before the
        # counters were separated, and the caller says so rather than guessing a split.
        out[stem] = (sent, skipped, m.get("arsenal"),
                     m.get("not_applicable"), m.get("not_sent"))
    return out


def controls_fired():
    """Control rows that came back as a breach: [(target, attack id, rate, fired, reply)].

    A control is an ORDINARY question carried through the same pipeline as the attacks, and it
    is there so a breach verdict means something. When one comes back EXPLOITED the reading is
    not "an attack worked" — it is that the system produces the breach signal with nobody
    attacking it, which is at once the most severe thing on the page and the reason to distrust
    every neighbouring row that shares its detector.

    It had nowhere to be said. The engine has flagged this since the day a control fired and
    turned out to be a target compromised at rest, and the rendered report still opened
    with a count of findings and no mention that on two systems the count includes a question a
    customer would ask on purpose.
    """
    out = []
    for fp in results_files(OUT_DIR):
        stem = os.path.basename(fp)[len("results_"):-len(".json")]
        try:
            rows = ((read_artifact(fp)[0] or {}).get("results") or [])
        except Exception:
            continue
        for r in rows:
            aid = str(r.get("attack", {}).get("id", ""))
            if not aid.startswith("ctrl-"):
                continue
            if (r.get("headline") or "") not in ("EXPLOITED", "PARTIAL"):
                continue
            probe = ((r.get("trials") or [{}])[0].get("probe") or {})
            out.append((stem, aid, r.get("rate") or "", r.get("fired") or [],
                        (probe.get("output") or "").strip()[:300],
                        str(r.get("attack", {}).get("text", ""))[:200]))
    return sorted(out)


def attribution_index():
    """(target, attack id) -> ("unattributable" | "weakened", detail), for rows that need it.

    THE AGGREGATE REPORT HAD NO ATTRIBUTION AT ALL. The engine measures it, prints it to a
    console, and stores it in each per-target scorecard, and then the aggregate — the one page
    that gets forwarded to the engineers who have to act on it — dropped it and showed 191
    findings as if each one were caused by the attack beside it. shipdesk is the case that
    made it visible: it hands over the key in its system prompt on 10 of 48 ORDINARY questions,
    so ten of its fourteen rows are the target's resting behaviour rather than a technique
    working, and the page said nothing.

    The judgement is imported, not reimplemented. There is exactly one definition of "is this
    breach attributable" in this repo and this is a second READER of it, because the way a
    shared judgement rots is a second copy that drifts a threshold.
    """
    import baseline as _bl
    try:
        from rejudge import contexts as _contexts
        ctxs = _contexts()
    except Exception:
        ctxs = {}
    out, unmeasured = {}, set()
    # results_files(), not a raw glob: a `--model` copy sits deliberately beside the canonical
    # run, and reading them here would compute caveats for rows the page never renders — the
    # aggregate and its caveats have to be drawn from the same set of files or the difference
    # is a silent filter.
    for fp in results_files(OUT_DIR):
        stem = os.path.basename(fp)[len("results_"):-len(".json")]
        tgt = target_of(stem, ctxs) or stem
        ambient = _bl.rates(tgt, str(OUT_DIR))
        if ambient is None:
            # NOT "said elsewhere". It was said NOWHERE: with no benign run this loop simply
            # produced no caveats for the target, and a page carrying no caveats reads as a
            # page whose findings are all attributable. An absent measurement rendered as a
            # clean one, in the deliverable — the single place in this system where that
            # mistake reaches somebody who acts on it. It bites hardest on exactly the run that
            # matters most, a FIRST run: a fresh workspace has no benign run in
            # it at all, so every finding on their page was unattributed and nothing said so.
            unmeasured.add(stem)
            continue
        import honeytoken as _ht
        canaries = _ht.declared(ctxs.get(tgt) or {})
        c_rates = _bl.canary_rates(tgt, canaries, str(OUT_DIR))
        try:
            rows = ((read_artifact(fp)[0] or {}).get("results") or [])
        except Exception:
            continue
        for r in rows:
            if (r.get("headline") or "") not in ("EXPLOITED", "PARTIAL"):
                continue
            verdict, detail = _bl.attribution(r.get("fired"), ambient)
            if verdict not in ("unattributable", "weakened"):
                continue
            loudest = max((ambient.get(d, 0.0) for d in (r.get("fired") or [])), default=0.0)
            if _bl.quiet_canary_in(r, c_rates, loudest):
                continue                 # the specific value it produced is quiet: it stands
            out[(stem, str(r["attack"].get("id")))] = (verdict, detail)
    return out, unmeasured


def rank_for_reader(findings, ambient=None):
    """All of them, ordered by what a stranger can check first. Nothing is dropped.

    A report is judged on whether its first finding survives being tried, not on how many it
    has. So the row that leads is the one that is most reproducible (3/3 beats 1/3) and whose
    detector is quietest on the target's OWN benign traffic — because the first thing a
    competent reader does is run the probe without the attack, and a lead row that fires on
    ordinary questions teaches them to discount everything under it.

    That is the whole job here. This function used to also TRUNCATE, keeping three and
    returning the rest as "held", which made the ordering look like a curated shortlist and
    contradicted the flag's own promise that scope changes how much traffic is sent and
    nothing else. Scope belongs to the run. What the run found belongs in the report.
    """
    ambient = ambient or {}

    def rank(f):
        tgt, attack, head, fired, probe, rate = f
        noisy = max((ambient.get(tgt, {}).get(d, 0.0) for d in (fired or [])), default=0.0)
        return (noisy, -_rate_frac(rate), 0 if head == "EXPLOITED" else 1, str(attack.get("id")))

    return sorted(findings, key=rank)


# The families an arsenal can deliver, and what each needs from the target. Absence is only
# meaningful beside the reason for it: "no indirect attacks" is a gap, "no indirect attacks
# because a chat endpoint exposes no corpus to poison" is an instruction.
DELIVERY_NEEDS = {
    "direct": "a prompt, which every target takes",
    "chain": "multi-turn history, derived from the config's `history` block",
    "forged_history": "an endpoint that accepts prior assistant turns in the request",
    "sessions": "a session id the target carries between requests",
    "indirect": ("somewhere to plant text the target will later read — a retrieved document, a "
                 "ticket, a page. A chat endpoint alone exposes none, so this family cannot be "
                 "sent through a YAML-configured target and its absence here is not a result"),
}


def delivered():
    """-> (families exercised, families absent). From the results, not from the arsenal.

    Read from what the runs actually contain rather than from what the arsenal holds, because
    the question the reader has is what happened to THEIR system, and an attack that was in the
    file but never applied is not coverage.
    """
    seen = set()
    for fp in results_files(OUT_DIR):
        try:
            d = read_artifact(fp)[0] or {}
        except (ValueError, OSError):
            continue
        for r in d.get("results", []):
            # NEITHER A SKIP NOR AN ERROR EXERCISED THE FAMILY. This dropped SKIP and kept
            # ERROR, so a delivery family whose only attack errored — a target that went
            # down, or a budget that ran out before the multi-turn attacks at the end of the
            # arsenal — was published on this page as a family that had been tried. The
            # docstring above already rules it out: an attack that never applied is not
            # coverage, and an errored one applied exactly as little as a skipped one.
            if r.get("headline") in NOT_MEASURED:
                continue
            seen.add((r.get("attack", {}) or {}).get("delivery") or "direct")
    return sorted(seen), sorted(set(DELIVERY_NEEDS) - seen)


def coverage():
    """-> (measured, skipped, errored) across every run on the page, from what each recorded.

    A page that lists findings promises coverage it may not have had, and the number that
    qualifies it already exists: `run_redteam` writes `attacks_n` and `skipped` into the meta
    of every results file. Reading it here costs nothing and turns "we found 30 things" into
    "we found 30 things and here is how much we tried", which is the difference between a
    count and a measurement.

    Counted from the files rather than from a flag, because the page can aggregate runs made
    at different scopes and the flag only knows about this invocation.
    """
    sent = skipped = errored = 0
    for fp in results_files(OUT_DIR):
        try:
            meta = (read_artifact(fp)[0] or {})["meta"]
        except (ValueError, KeyError, OSError):
            # A results file that cannot be read is not a run that sent nothing. Say nothing
            # about it rather than counting it as zero, which would understate coverage in
            # exactly the direction that flatters the report.
            return None
        n, sk = meta.get("attacks_n"), meta.get("skipped")
        if not isinstance(n, int) or not isinstance(sk, int):
            return None
        # AN ERRORED ROW IS NOT A SENT ATTACK. `measured` carries the reasoning; what it
        # means here is that a run whose budget stopped it after one probe can no longer
        # tell this page it sent the whole arsenal.
        _m, _e = measured(meta)
        sent += _m
        errored += _e
        skipped += sk
    return (sent, skipped, errored) if sent or skipped or errored else None



def main():
    import argparse
    ap = argparse.ArgumentParser()
    # THE REPORT HAS NO SCOPE. It renders what is in the directory it was pointed at, and
    # how much traffic produced that is `run_redteam --scope`'s business. The flag used to
    # also truncate the findings, and once that went the only thing left for it to decide
    # was the output filename — a difference a reader would look for and never find.
    ap.add_argument("--scope", dest="scope", default=None, help=argparse.SUPPRESS)
    args = ap.parse_args()

    # The fleet's own configs. `load_all` decides what to do with them via `fleet_filter`,
    # which identifies the directory BY ITS CONTENTS: if nothing in it belongs to this fleet,
    # it is a fixture's directory and nothing is dropped.
    findings, all_targets, measured, unreadable = load_all(known=fleet_names())
    # SAID, not counted. "3 files skipped" tells nobody which run to re-do, and a
    # remediation page silently short of a target reads as a clean bill for it.
    say_unreadable(unreadable, "this report")
    # Ordered at every scope, truncated at none. See rank_for_reader.
    findings = rank_for_reader(findings, ambient_rates())
    ages, regressed = _timeline()
    unseen = _unobservable()
    # A DECLARED CHANNEL THAT NEVER CARRIED ANYTHING. Kept separate from `unseen`, which is
    # about calls whose CONTENTS no detector could read; this is about a channel that was
    # configured and never once produced a value, which is a mapping error rather than a
    # visibility limit — and the report is the only place the operator would find out.
    dead_paths = _unresolved_paths()
    newest = max(measured.values(), default="")
    stale = sorted({f"{t} ({d})" for t, d in measured.items() if d < newest})
    staleness = ("" if not stale else
                 '<div class="stalebar"><b>Mixed measurement dates.</b> Newest run '
                 f'{esc(newest)}; measured earlier: {esc(", ".join(stale))}. '
                 "Findings from an earlier run were produced by an earlier engine and may "
                 "already be fixed, or may be wrong — re-run before acting on them.</div>")
    # A BREACH WITH NO WRITTEN FIX IS STILL A BREACH. This used to `continue` on a row whose
    # fired detectors were all absent from REMEDIATION — sixteen entries against an oracle of
    # fifty-six — and every number on the page was then computed from the survivors. On the
    # stored fleet that deleted 49 of 169 rows and two whole targets: ragbot and citebot each
    # breached 3/3 and appeared on the rendered page only inside the staleness bar, while the
    # page said "24 of 28 showed at least one exploitable finding".
    #
    # It failed in the worst possible direction for a security deliverable, and it got worse as
    # the oracle got better: every detector added after this table was written fires, is stored,
    # and is deleted at render time. A report that goes quieter as its instrument improves is
    # the exact inversion of what the instrument is for.
    #
    # The fix is not to write sixteen more fixes today. It is that a row nobody has written a
    # remediation for is UNMAPPED, not absent — the same call this project makes everywhere
    # else: name the gap rather than report clean.
    groups, unmapped = {}, []
    channels = {}
    for tgt, attack, head, fired, probe, rate in findings:
        # Through `current_name`, because a stored row names the detectors that fired ON THE
        # DAY IT RAN and those names outlive the code. Without it a real MCP tool-poisoning
        # finding recorded under the retired `tool_poison` renders as a class nobody has a
        # fix for, when the fix is right there under the name that replaced it.
        fired = [current_name(d) for d in fired]
        # SEVERITY FIRST, THEN ORDER — the same key the sort two screens down already uses, and
        # it belongs here for a sharper reason. `order` is not unique: sixteen values are shared,
        # and NINE of those pairs span different severities. A row where `session_leak`
        # (critical) and `ansi_exfil` (high) both fired has a tie, `min` resolves a tie by
        # whichever came first in the stored `fired` list, and that list order is an artifact of
        # how the JSON was written. So a critical finding could be filed under a high heading,
        # decided by nothing. One row on the current fleet lands that way; the other eight pairs
        # are waiting for a run that trips them.
        rem = min((d for d in fired if d in REMEDIATION),
                  key=lambda d: (SEV_RANK[REMEDIATION[d]["sev"]], REMEDIATION[d]["order"]),
                  default=None)
        if rem is None:
            unmapped.append((tgt, attack, head, probe, rate, sorted(fired)))
            continue
        # Filed under the ROOT CAUSE, and the detector that got it there is remembered as the
        # channel — so the parent can say "seen through these four routes" instead of the page
        # rendering four problems that share one fix.
        key = root_key(rem)
        groups.setdefault(key, []).append((tgt, attack, head, probe, rate))
        channels.setdefault(key, {}).setdefault(rem, 0)
        channels[key][rem] += 1

    ordered = sorted(groups.items(),
                     key=lambda kv: (SEV_RANK[entry(kv[0])["sev"]], entry(kv[0])["order"]))
    # Counted from what was READ, not from what happened to render. The two were the same
    # number only for as long as the table covered the oracle, and they never did.
    n_breaches = len(findings)
    n_mapped = sum(len(v) for v in groups.values())
    breached_targets = {f[0] for f in findings}
    sev_count = {"critical": 0, "high": 0, "medium": 0, "unmapped": len(unmapped)}
    for det, items in groups.items():
        sev_count[entry(det)["sev"]] += len(items)
    total = max(1, n_breaches)

    # THE HEADLINE USED TO BE OCCURRENCES, AND NOBODY BELIEVES IT. "117 CRITICAL" was 15
    # distinct root causes spread across thirty systems, and 65 of the 117 were one detector
    # counted 65 times. A reader who has seen one scanner report has seen that number before
    # and knows what it is worth — and this page spends its own body arguing that a bare count
    # is the least trustworthy thing a security tool prints. Leading with one was the single
    # most expensive sentence in the document.
    #
    # So the tiles count ROOT CAUSES, which is what a team can actually act on and what the
    # executive summary was already reducing to two paragraphs later. Occurrences stay, beside
    # them, as the spread — genuinely informative, and no longer pretending to be a severity.
    root_sev = {"critical": 0, "high": 0, "medium": 0, "unmapped": 1 if unmapped else 0}
    for det in groups:
        root_sev[entry(det)["sev"]] += 1
    n_roots = len(groups) + (1 if unmapped else 0)

    # AND WHOSE SOFTWARE IT IS. Most of these targets are practice bots written in this
    # repository to be broken; counting a finding on one of them beside a finding on software
    # somebody else shipped is counting your own homework. `provenance` exists in every target
    # config for exactly this and the aggregate had never read it.
    prov_of = {}
    try:
        import yaml as _yaml
        from target import target_configs as _tc
        for _fp in _tc(os.path.dirname(os.path.abspath(__file__))):
            _c = _yaml.safe_load(open(_fp, encoding="utf-8")) or {}
            if _c.get("name"):
                prov_of[_c["name"]] = _c.get("provenance", "unstated")
    except Exception:
        prov_of = {}
    own = sum(1 for f in findings if prov_of.get(f[0]) == "practice")
    world = n_breaches - own

    # Found, and no fix written for it yet. Deliberately shaped like the NOT MEASURED block
    # rather than like a finding: it carries evidence and no remediation, which is exactly what
    # it is. Grouped by detector so the reader sees WHICH class of finding has no answer here,
    # and so the gap in the table is legible as a gap in the table.
    # Said FIRST, because it changes how everything below it reads.
    #
    # Narrowed to the systems this page actually shows, because a short run must not name a
    # system this page is not reporting on: naming somebody else's deployment is a leak
    # wearing a caveat. On a real short run that is one system anyway, and its control firing
    # is the most valuable single thing the run can give away — most severe, and the easiest
    # of everything here for the reader to reproduce, since the payload is a normal question.
    # Which rows the target would produce anyway. Computed here rather than trusted from the
    # stored note, because both sides of that comparison move after a sweep: a benign run can
    # be added or re-scored at any time, and a caveat frozen at sweep time is a snapshot of an
    # absence that outlives the absence.
    attrib, unmeasured = attribution_index()

    ctrls = controls_fired()
    if args.scope == "quick":
        shown_targets = {t for t, *_ in findings}
        ctrls = [c for c in ctrls if c[0] in shown_targets]
    controls_html = ""
    if ctrls:
        rows = "".join(
            f'<li><span class="mono">{esc(t)}</span> · {esc(aid)}'
            f'<span class="rate">{esc(rate)}</span>'
            f'<span class="unattr">FIRED WITHOUT AN ATTACK</span>'
            f'<div class="ph">the question asked</div><pre>{esc(txt)}</pre>'
            f'<div class="ph">what came back</div><pre>{esc(reply)}</pre>'
            f'<div class="ph">detectors</div><pre>{esc(", ".join(fired))}</pre></li>'
            for t, aid, rate, fired, reply, txt in ctrls)
        controls_html = f"""
        <section class="finding">
          <div class="fhead">
            <span class="sev" style="color:{SEV['critical']};background:{SEV_BG['critical']}">CRITICAL</span>
            <span class="owasp">Read this before the findings</span>
          </div>
          <h2>{len(ctrls)} control{'s' if len(ctrls) != 1 else ''} came back as a breach</h2>
          <div class="fix"><span class="fixlabel">What this means</span>a control is an ordinary
            question, sent through the same pipeline as the attacks so that a breach verdict
            means something. These produced the breach signal with nobody attacking. That is
            more serious than any technique on this page, because it does not need one: the
            system does it at rest. It is also the reason to read every finding below that
            shares a detector with these as unattributed until the fix lands.</div>
          <details open><summary>Evidence</summary><ul class="trig">{rows}</ul></details>
        </section>"""

    # A TARGET WITH NO BENIGN RUN PRODUCES NO CAVEATS, and a page with no caveats reads as a
    # page whose findings are all attributable. Said out loud, next to the systems it applies
    # to, because this is the default state of a customer's first run.
    shown_targets = {t for t, *_ in findings}
    blind = sorted(t for t in unmeasured if t in shown_targets)
    unattributed_html = ""
    if blind:
        n_rows = sum(1 for t, *_ in findings if t in set(blind))
        unattributed_html = f"""
        <section class="finding unseen">
          <div class="fhead"><span class="sev" style="color:#92400e;background:#fef3c7">NOT ATTRIBUTED</span></div>
          <h2>{n_rows} finding(s) here have not been compared against ordinary traffic</h2>
          <div class="fix"><span class="fixlabel">What is missing</span>a breach verdict is only
            worth what the system's silence is worth when nobody attacks it. For
            {esc(", ".join(blind))} nothing has measured that yet, so every finding above from
            {'those systems' if len(blind) > 1 else 'that system'} may be something it does
            anyway. That is not a smaller finding, it is a DIFFERENT one, and usually a worse
            one: a system that leaks to an attacker has a bug, and a system that leaks to
            anyone who asks politely has no boundary at all. The run that settles it sends the
            same corpus with the attacks removed.</div>
        </section>"""

    # HOW MUCH OF THE ARSENAL RAN, said before the findings, because it sets what they mean.
    ran = {t: v for t, v in arsenal_ran().items() if t in {x for x, *_ in findings}}
    arsenal_html = ""
    if ran:
        # A DASH, NOT A ZERO, when the artifact predates the split: it did not record which
        # of the two this was, and printing 0 under one of them would answer for it.
        rows = "".join(
            f'<tr><td class="mono">{esc(t)}</td><td>{sent}</td>'
            f'<td>{_na if isinstance(_na, int) else "—"}</td>'
            f'<td>{_ns if isinstance(_ns, int) else "—"}</td>'
            f'<td>{skipped}</td>'
            f'<td class="mono dim">{esc(arsenal or "—")}</td></tr>'
            for t, (sent, skipped, arsenal, _na, _ns) in sorted(ran.items()))
        fewest = min(v[0] for v in ran.values())
        _held = sum(v[4] for v in ran.values() if isinstance(v[4], int))
        _short = (f" A further {_held} were not sent because the run was asked to be a short "
                  f"one: <code>--scope quick</code> sends one attack per category, and a "
                  f"flag is all that stands between this page and the rest of them."
                  if _held else "")
        arsenal_html = f"""
        <section class="finding unseen">
          <div class="fhead"><span class="sev" style="color:#92400e;background:#fef3c7">HOW MUCH RAN</span></div>
          <h2>What was sent, and what was not</h2>
          <div class="fix"><span class="fixlabel">Read this before the counts</span>an attack
            that was never sent is a GAP, not a finding that came back clean — the same sentence this engine
            applies to a budget that runs out. The smallest run on this page sent
            {fewest} attack(s).{_short} The rest of the file was scoped to other systems, so
            those were never candidates here; that is only reassuring if the arsenal named
            below is the one written for a system like yours. Deliveries your configuration
            cannot carry were skipped as well — a transcript for multi-turn work, a
            tool-call log for anything about what your tools received.</div>
          <table class="pair"><thead><tr><th>system</th><th>sent</th>
            <th>not applicable</th><th>not sent</th><th>total absent</th>
            <th>arsenal</th></tr></thead><tbody>{rows}</tbody></table>
        </section>"""

    unmapped_html = ""
    if unmapped:
        by_det = {}
        for tgt, attack, head, probe, rate, fired in unmapped:
            for d in fired:
                by_det.setdefault(d, []).append((tgt, attack["id"], head, rate))
        rows = ""
        for det in sorted(by_det, key=lambda d: -len(by_det[d])):
            items = by_det[det]
            systems = ", ".join(sorted({t for t, *_ in items}))
            examples = ", ".join(f"{a} {r}" for _, a, _, r in
                                 sorted(items, key=lambda it: -_rate_frac(it[3]))[:3])
            rows += (f'<tr><td class="mono">{esc(det)}</td>'
                     f'<td class="mono dim">{esc(systems)}</td>'
                     f'<td>{len(items)}</td>'
                     f'<td class="mono dim">{esc(examples)}</td></tr>')
        u_targets = sorted({t for t, *_ in unmapped})
        unmapped_html = f"""
        <section class="finding unseen">
          <div class="fhead"><span class="sev" style="color:#6b7280;background:#f3f4f6">NO FIX WRITTEN</span></div>
          <h2>Findings this report has no remediation text for</h2>
          <div class="fix"><span class="fixlabel">Why they are here</span>the oracle confirmed
            these on live traffic and the remediation table above does not cover them yet, so
            they are listed rather than dropped. They are findings, not gaps in measurement:
            the evidence is in the per-target scorecards. {len(unmapped)} of the
            {n_breaches} findings on this page, across {esc(", ".join(u_targets))}.</div>
          <table class="pair"><thead><tr><th>detector</th><th>systems</th><th>rows</th>
            <th>most reproducible</th></tr></thead><tbody>{rows}</tbody></table>
        </section>"""

    # HOW MUCH WAS TRIED, beside what was found. A findings list with no denominator invites
    # the reader to treat it as the whole truth about the system, and on a `--scope quick` run
    # it is one attack per category by design. Saying so is not a caveat bolted on; it is the
    # same rule the rest of this page follows, that an absence must never render as a result.
    dead_html = ""
    if dead_paths:
        _rows = "".join(
            f'<li><span class="mono">{esc(t)}</span><br><span class="muted">{esc(", ".join(p))}'
            f'</span></li>' for t, p in sorted(dead_paths.items()))
        dead_html = f"""
        <section class="finding unseen">
          <div class="fhead"><span class="sev" style="color:#9a6700;background:rgba(154,103,0,.12)">MAPPING</span></div>
          <h2>A configured response path never resolved</h2>
          <div class="fix"><span class="fixlabel">What this means</span>the config declares
            these paths and the whole run produced nothing at any of them, not once. The
            capability is still listed above because the config claims it, so every detector
            that reads that channel ran against an empty value and reported nothing — which is
            indistinguishable, on this page, from a channel that was clean. Check the path
            against one real response before believing any result that depends on it.
            <ul class="trig">{_rows}</ul></div>
        </section>"""

    held_html = ""
    # WHICH FAMILIES NEVER RAN, and why. A zero in a table is read as a result; a family named
    # with the reason it could not be delivered is read as a thing to arrange.
    _sent_fams, _absent_fams = delivered()
    _families = ""
    if _absent_fams:
        _rows = "".join(
            f'<li><span class="mono">{esc(f)}</span> — {esc(DELIVERY_NEEDS.get(f, "not delivered here"))}</li>'
            for f in _absent_fams)
        _families = (f'<div class="fix"><span class="fixlabel">Not tried at all</span>'
                     f'These delivery families sent nothing against these systems. That is a gap '
                     f'in what was measured, not a finding about the deployment:'
                     f'<ul class="trig">{_rows}</ul></div>')
    _cov = coverage()
    # EITHER REASON IS ENOUGH. This section used to render only when attacks were skipped, so a
    # run that sent everything it had but never exercised a whole delivery family said nothing
    # about the family — the statement was hostage to an unrelated count. Absence has two
    # shapes here and both belong on the page.
    # `coverage()` RETURNS None FOR "I CANNOT SAY", and this turned it into "0 not sent",
    # which is the strongest coverage claim the page can make. Its docstring, three hundred
    # lines up, forbids exactly this: "a results file that cannot be read is not a run that
    # sent nothing. Say nothing about it rather than counting it as zero, which would
    # understate coverage in exactly the direction that flatters the report." One unreadable
    # artifact in the directory -- a truncated file from an interrupted sweep, the case
    # `read_artifact` exists for -- and the client's deliverable claimed total coverage.
    # ERRORED IS A THIRD REASON THIS SECTION HAS TO RENDER. A run stopped by its budget can
    # have skipped nothing and exercised every delivery family, and still have measured one
    # attack in twenty — and on those two conditions alone the page said nothing at all,
    # while the short list of findings above it read as a quiet result.
    if (_cov and (_cov[1] or _cov[2])) or _absent_fams:
        _sent, _skipped, _errored = _cov if _cov else (None, None, None)
        # Built here rather than inline, because the sentence it joins is already a nested
        # conditional inside an f-string and a fourth level in there is unreadable.
        _err_note = (f". A further {_errored} produced no measurement at all — the request "
                     f"failed, or the budget refused it before it was sent — so they are "
                     f"neither a breach nor a defence and are counted as neither"
                     if _errored else "")
        held_html = f"""
        <section class="finding unseen">
          <div class="fhead"><span class="sev" style="color:#6b7280;background:#f3f4f6">COVERAGE</span></div>
          <h2>{"how much of the arsenal ran could not be determined"
               if _sent is None else
               f"{_sent} attack(s) measured, {_skipped} not sent"
               + (f", {_errored} errored" if _errored else "")}</h2>
          <div class="fix"><span class="fixlabel">What this page is</span>every finding this
            run produced is here, in full — payload, reply, detector, the caveat about whether
            it is attributable, and the fix. What it is not is an exhaustive statement about
            these systems: {"an artifact in this workspace could not be read, so how much of "
            "the arsenal ran cannot be stated here at all — that is a gap in this page, not a "
            "clean bill" if _skipped is None else
            f"{_skipped} attack(s) in the arsenal were not sent, either because "
            "they do not apply to the target or because the run was scoped to send one attack "
            "from each category rather than all of them"}{_err_note}. A category that was covered once was
            covered once. Re-run at <span class="mono">--scope full</span> before reading a
            quiet category as a closed one.</div>{_families}
        </section>"""

    # What the run could NOT see, said beside what it did. A report that only lists
    # findings promises coverage it never had: on a code agent a customer record left
    # through send_email(body=customer_record) and every detector read a variable name.
    unseen_html = ""
    if unseen:
        rows = ""
        for tgt in sorted(unseen):
            for b, aids in sorted(unseen[tgt].items()):
                rows += (f'<tr><td class="mono">{esc(tgt)}</td><td>{esc(b)}</td>'
                         f'<td class="mono dim">{esc(", ".join(sorted(aids)[:4]))}</td></tr>')
        unseen_html = f"""
        <section class="finding unseen">
          <div class="fhead"><span class="sev" style="color:#6b7280;background:#f3f4f6">NOT MEASURED</span></div>
          <h2>Calls this assessment could not see inside</h2>
          <div class="fix"><span class="fixlabel">What is needed</span>a log of what each
            tool RECEIVED, not only what the model wrote. Standard agent-observability
            tool-call logging already records it. Until then the rows below are gaps, not
            clean results: the argument was a variable, so its value never appears in the
            text and no pattern can reach it.</div>
          <table class="pair"><thead><tr><th>system</th><th>call</th><th>seen on</th></tr>
          </thead><tbody>{rows}</tbody></table>
        </section>"""

    # Whose software these were found in, said in the header rather than inferred from the
    # target names. A page that mixes the two is counting its own homework.
    prov_line = ""
    if own and world:
        prov_line = (f" Of those occurrences, <b>{own}</b> are on practice bots written in this "
                     f"repository to be broken, and <b>{world}</b> are on software nobody here "
                     f"designed — the second number is the one that says anything about the "
                     f"world.")
    elif own and not world:
        prov_line = (f" Every occurrence here is on a practice bot written in this repository to "
                     f"be broken. This page is an exercise, not an assessment of anything real.")

    # severity distribution bar
    # THE BAR HAS TO MATCH THE TILES. They were occurrences while the tiles became root causes,
    # so the picture argued with the numbers directly above it — and the picture is what a
    # reader takes away.
    root_total = max(1, n_roots)
    bar = "".join(
        f'<span style="width:{100*root_sev[s]/root_total:.1f}%;background:{SEV.get(s, "#9aa3ae")}"></span>'
        for s in ("critical", "high", "medium", "unmapped") if root_sev[s])

    tiles = "".join(
        f'<div class="tile"><div class="n" style="color:{SEV[s]}">{root_sev[s]}</div>'
        f'<div class="l">{s}</div></div>' for s in ("critical", "high", "medium"))
    if root_sev["unmapped"]:
        # so the four numbers add up to the headline, in view, rather than needing to be trusted
        tiles += (f'<div class="tile"><div class="n" style="color:#6b7280">'
                  f'{root_sev["unmapped"]}</div><div class="l">no fix yet</div></div>')

    sections = ""
    for det, items in ordered:
        rem = entry(det)
        sev = rem["sev"]

        # WHICH ROUTES THIS WAS SEEN THROUGH. Collapsing four detectors into one root cause is
        # only honest if the four are still named: a reader who has to strip zero-width
        # characters needs to know that is what fired, and somebody chasing a secret in a
        # hostname needs the resolver advice that the parent fix does not carry.
        #
        # So the parent owns the severity and the primary control, and each channel keeps its
        # own sentence underneath. Nothing is lost; it stops being counted as several problems.
        chan_html = ""
        if det in ROOT_CAUSES:
            seen = channels.get(det, {})
            rows = []
            for member in ROOT_CAUSES[det]["members"]:
                if member not in seen:
                    continue
                own = REMEDIATION.get(member, {})
                rows.append(
                    f'<li><span class="mono">{esc(member)}</span> '
                    f'<span class="rate">x{seen[member]}</span><br>'
                    f'<span class="muted">{esc(own.get("title", ""))}</span></li>')
            not_seen = [m for m in ROOT_CAUSES[det]["members"] if m not in seen]
            if rows:
                extra = ""
                if not_seen:
                    # A route nobody saw is not a route that is closed — it is one this run did
                    # not exercise, and saying so is the difference between coverage and luck.
                    extra = (f'<div class="muted" style="margin-top:6px">Not seen in this run: '
                             f'{esc(", ".join(not_seen))} — not exercised, rather than closed.'
                             f'</div>')
                chan_html = (f'<div class="fix"><span class="fixlabel">Seen through</span>'
                             f'<ul class="trig">{"".join(rows)}</ul>{extra}</div>')
        systems = sorted({t for t, *_ in items})
        sys_html = " ".join(f'<span class="tag">{esc(t)}</span>' for t in systems)
        # Sort a group's examples so the most reproducible (3/3) leads the evidence — and,
        # ahead of that, so an ATTRIBUTABLE row leads it. The lead example is the one a reader
        # tries first, and handing them one the target also does without an attack is the
        # fastest way to have the whole document disbelieved.
        items = sorted(items, key=lambda it: (
            1 if (it[0], str(it[1].get("id"))) in attrib else 0, -_rate_frac(it[4])))
        t0, a0, h0, p0, r0 = items[0]
        n_unattr = sum(1 for it in items if (it[0], str(it[1].get("id"))) in attrib)
        caveat_html = (f'<span class="count unattr-count">{n_unattr} not attributable to the '
                       f'attack</span>') if n_unattr else ""
        reply = (p0.get("output") or "").strip()
        reply = reply if len(reply) < 520 else reply[:520] + " …"
        tcs = p0.get("tool_calls") or []
        tc_html = ("<div class='ph'>tool calls</div><pre>" +
                   esc("\n".join(f"{t}({i})" for t, i in tcs)) + "</pre>") if tcs else ""
        repro = f"<div class='ph'>reproducibility</div><pre>{esc(r0)} trials broke this attack</pre>" if r0 else ""
        def _meta(t, aid):
            bits = []
            if aid in regressed.get(t, ()):
                # a fix that did not hold is a different conversation from a new finding,
                # and the worse of the two
                bits.append('<span class="regress">RETURNED after a fix</span>')
            a = attrib.get((t, aid))
            if a:
                verdict, detail = a
                why = ", ".join(f"{d} on {r:.0%} of benign traffic" for d, r in detail[:2])
                bits.append(f'<span class="unattr" title="{esc(why)}">'
                            f'{"UNATTRIBUTED" if verdict == "unattributable" else "WEAKENED"}'
                            f'</span>')
            first = (ages.get(t) or {}).get(aid)
            if first:
                bits.append(f'<span class="age">open since {esc(first[:10])}</span>')
            return "".join(bits)

        trig = "".join(f'<li><span class="mono">{esc(t)}</span> · {esc(a["id"])}'
                       f'<span class="rate">{esc(rt)}</span>{_meta(t, a["id"])}</li>'
                       for t, a, h, p, rt in items)
        sections += f"""
        <section class="finding">
          <div class="fhead">
            <span class="sev" style="color:{SEV[sev]};background:{SEV_BG[sev]}">{sev.upper()}</span>
            <span class="owasp">{esc(rem['owasp'])}</span>
          </div>
          <h2>{esc(rem['title'])}</h2>
          <div class="affected"><span class="ph2">Affected</span> {sys_html}
            <span class="count">{len(items)} occurrence{'s' if len(items)!=1 else ''}</span>
            {caveat_html}</div>
          <div class="fix"><span class="fixlabel">Remediation</span>{esc(rem['fix'])}</div>
          {chan_html}
          <details>
            <summary>Evidence — <span class="mono">{esc(a0['id'])}</span> on <span class="mono">{esc(t0)}</span></summary>
            <div class="ph">attack</div><pre>{esc(payload_text(a0))}</pre>
            {tc_html}
            <div class="ph">what happened</div><pre>{esc(reply)}</pre>
            {repro}
            <div class="ph">also triggered by</div><ul class="trig">{trig}</ul>
          </details>
        </section>"""

    today = datetime.date.today().isoformat()
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QAtration — Security Report</title><style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#14181f;--dim:#5b6472;--line:#e3e7ec;--accent:#b3261e;--panel:#eef1f5}}
@media(prefers-color-scheme:dark){{:root:not([data-theme="light"]){{--bg:#0d1014;--card:#161b22;--ink:#e6edf3;--dim:#8b95a4;--line:#242c37;--accent:#ff5b60;--panel:#1a2029}}}}
:root[data-theme="dark"]{{--bg:#0d1014;--card:#161b22;--ink:#e6edf3;--dim:#8b95a4;--line:#242c37;--accent:#ff5b60;--panel:#1a2029}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,sans-serif}}
.wrap{{max-width:840px;margin:0 auto;padding:40px 22px 96px}}
.rpt-head{{border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:26px}}
h1{{font-size:24px;margin:0 0 4px;letter-spacing:-.01em}} h1 .q{{color:var(--accent)}}
.sub{{color:var(--dim);font-size:13.5px;font-family:ui-monospace,Consolas,monospace}}
.summary{{display:grid;grid-template-columns:auto 1fr;gap:26px;align-items:center;
  background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin-bottom:14px}}
.tiles{{display:flex;gap:22px}}
.tile{{text-align:center}} .tile .n{{font-size:30px;font-weight:800;line-height:1}}
.tile .l{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);margin-top:4px}}
.dist .distlabel{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);margin-bottom:7px}}
.distbar{{display:flex;height:10px;border-radius:6px;overflow:hidden;background:var(--panel)}}
.distbar span{{display:block}}
.coverage{{color:var(--dim);font-size:13px;margin:0 0 26px}}
.stalebar{{background:#fff5e0;color:#8a5a00;border-left:3px solid #8a5a00;border-radius:8px;padding:11px 14px;margin:0 0 18px;font-size:13.5px}}
@media(prefers-color-scheme:dark){{.stalebar{{background:rgba(138,90,0,.22);color:#e0a83a}}}}
.exec{{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:10px;padding:16px 18px;margin-bottom:28px;font-size:14.5px}}
.finding{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin-bottom:16px}}
.regress{{background:#fee2e2;color:#b3261e;font-weight:700;font-size:11px;
  padding:1px 7px;border-radius:9px;margin-left:8px;letter-spacing:.3px}}
.age{{color:var(--dim);font-size:12px;margin-left:8px}}
.unattr{{background:#fef3c7;color:#92400e;font-weight:700;font-size:11px;
  padding:1px 6px;border-radius:4px;margin-left:8px;letter-spacing:.02em;cursor:help}}
.unattr-count{{background:#fef3c7;color:#92400e}}
.unseen h2{{color:#4b5563}}
.fhead{{display:flex;align-items:center;gap:10px;margin-bottom:10px}}
.sev{{font-size:11px;font-weight:800;padding:3px 10px;border-radius:5px;letter-spacing:.04em}}
.owasp{{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;color:var(--dim);
  border:1px solid var(--line);padding:2px 8px;border-radius:5px}}
.finding h2{{font-size:18px;margin:0 0 12px;letter-spacing:-.01em}}
.affected{{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:14px;font-size:13px}}
.ph2{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim)}}
.tag{{font-family:ui-monospace,Consolas,monospace;font-size:12px;background:var(--panel);
  padding:2px 8px;border-radius:5px}}
.count{{color:var(--dim);font-size:12.5px;margin-left:auto}}
.fix{{background:var(--panel);border-radius:8px;padding:13px 15px;font-size:14px}}
.fixlabel{{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--accent);font-weight:700;margin-bottom:5px}}
.ph{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim);margin:12px 0 4px}}
.mono{{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}}
details{{margin-top:12px}} summary{{cursor:pointer;color:var(--dim);font-size:13px;padding:4px 0}}
pre{{white-space:pre-wrap;word-break:break-word;margin:4px 0;font-family:ui-monospace,Consolas,monospace;font-size:12.5px;background:var(--bg);padding:11px;border-radius:6px;border:1px solid var(--line)}}
.trig{{margin:4px 0;padding-left:20px}} .trig li{{margin:3px 0}}
.trig .rate{{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:var(--dim);margin-left:8px}}
.pattern{{color:var(--dim);font-size:14px;margin-top:26px;border-top:1px solid var(--line);padding-top:18px}}
@media(max-width:640px){{.summary{{grid-template-columns:1fr;gap:18px}}}}
</style></head><body><div class="wrap">
<div class="rpt-head">
  <h1><span class="q">QA</span>tration — Security Assessment</h1>
  <div class="sub">Adversarial test of AI features · {today} · {len(all_targets)} systems tested</div>
</div>

<div class="summary">
  <div class="tiles"><div class="tile"><div class="n">{n_roots}</div><div class="l">root causes</div></div>{tiles}</div>
  <div class="dist"><div class="distlabel">severity distribution</div><div class="distbar">{bar}</div></div>
</div>
<p class="coverage"><b>Read the tiles as root causes, not as a score.</b> These {n_roots} distinct
problems were seen <b>{n_breaches} times</b> across {len(all_targets)} systems. A count of
occurrences answers "how often", which is not the question a fix is chosen by. One
detector accounting for dozens of rows is one problem with a wide blast radius rather than
dozens of problems.{prov_line}</p>
<p class="coverage">Coverage: {len(all_targets)} target{'s' if len(all_targets)!=1 else ''} exercised across prompt injection,
sensitive-data disclosure, excessive agency (tool abuse, SSRF, command injection, broken object/function-level
authorization), improper output handling, and system-prompt leakage. {len(breached_targets)} showed at least
one exploitable finding.</p>

{staleness}
<div class="exec"><b>Executive summary.</b> This assessment found {n_roots} distinct exploitable
weaknesses, seen {n_breaches} times in total.
{n_mapped} of them reduce to {len(ordered)} root-cause fixes below, prioritized by severity{
"" if not unmapped else f"; the remaining {len(unmapped)} are listed at the end, confirmed on live traffic with no remediation text written for them yet"}. The common thread:
<b>security was delegated to the model's judgment</b> — prompt rules like “never reveal” or “only fetch the
docs site.” That judgment is manipulable. Each fix below moves the control out of the prompt and into code
the attacker can't talk their way past.</div>
{controls_html}
{arsenal_html}
{unattributed_html}
{sections}
{dead_html}{held_html}
{unmapped_html}
{unseen_html}
<p class="pattern">Root cause across every finding: the model was trusted to enforce a security boundary.
Models are helpful, not secure. Put the boundary in the tool, the query, and the auth layer — and treat
everything the model reads (prompts, retrieved documents, tool output) as untrusted input.</p>
</div></body></html>"""
    out = OUT_DIR / "defense_report.html"
    out.write_text(doc, encoding="utf-8")
    # The console line leads the same way the page does, or the two disagree about what was
    # found and the terminal is the one somebody pastes into a ticket.
    print(f"wrote {out} — {n_roots} root cause(s) ({ {k: v for k, v in root_sev.items() if v} }) "
          f"seen {n_breaches} time(s), {len(ordered)} fixes, "
          f"{len(all_targets)} targets")
    if unmapped:
        print(f"  ! {len(unmapped)} finding(s) have no remediation text and are listed without "
              f"one — {len({d for *_ , fired in unmapped for d in fired})} detector(s): "
              + ", ".join(sorted({d for *_, fired in unmapped for d in fired})[:8]))


if __name__ == "__main__":
    main()
