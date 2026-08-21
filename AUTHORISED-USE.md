# Authorised use only

This is an attack tool. It sends prompt injections, extraction attempts, authorization probes
and code-execution payloads at whatever endpoint it is pointed at, and it is written to be
effective.

**Point it only at a system you own, or one whose owner has given you written permission to
test.** Not at a public chatbot you find interesting. Not at a vendor's demo. Not at somebody's
production support bot to see what happens. Testing a system without the owner's permission is
unlawful in most places regardless of intent, and "I was only checking" has never been a
defence.

The engine tries to make that hard to get wrong rather than leaving it to a paragraph:

* `authorization.py` refuses any non-local target that cannot prove ownership. Proof means the
  endpoint echoing a token we issued, a file at `/.well-known/qatration-authorization`, or a
  DNS TXT record. A checkbox saying "I confirm I am authorised" is a record of a claim, and
  every abusive scan already has one of those.
* Proofs expire after fourteen days, because an assessment authorised last quarter was not
  authorised today.
* Every run records who authorised it, by which method and when, beside the findings. An
  assessment that cannot say who asked for it is worthless as evidence and dangerous as an
  artifact: in a log, it is indistinguishable from an attack.
* Run on a server rather than a workstation (`QATRATION_HOSTED=1`), the rule inverts and loopback, private and
  link-local addresses are refused outright — including `169.254.169.254`. On a workstation
  `localhost` is the practice fleet; on a server it is somebody's infrastructure.

## The practice fleet is there so you do not need somebody else's system

`draftbot/`, `httpbot/`, `external/`, `foreign-agent/` and `foreign-langchain/` are deliberately
weak bots with planted secrets. They exist so the engine can be developed, demonstrated and
learned against targets nobody has to ask permission for. Start there.

## If you find something in software you do not own

Report it to whoever owns it, privately, and give them time. That is true whether you found it
with this tool or any other.
