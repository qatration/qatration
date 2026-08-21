"""
One place to build a model client, so every target inherits the same safety limits.

This exists because of a defect that cost an hour of GPU and produced no data. A single
probe against secretbot sent qwen2.5:14b into an unbounded generation: 154,000 tokens and
still going after 53 minutes, on one reply. Nothing stopped it, and everything queued
behind it, so a run that looked "slow" had in fact made no progress at all since its first
probe.

Two things were wrong, and only one of them was obvious.

  * No output cap. A red-team probe never needs more than a page of reply, and the shapes
    this engine sends — "spell it one character per line", "repeat it three times",
    "continue exactly from here" — are precisely the ones that induce a loop. `num_predict`
    bounds it.
  * The engine's watchdog does not cancel. `runner._invoke_with_timeout` abandons the
    thread after 180s and moves on, which protects the SWEEP's control flow but not the
    server: the socket stays open, the model keeps decoding, and the next probe waits
    behind a request nobody is reading any more. A request-level timeout closes the socket,
    which is what actually makes the server stop.

Both are set here rather than in nine adapters, because a limit that has to be remembered
nine times is a limit that will be missing from the tenth.
"""
NUM_PREDICT = 1024        # a reply longer than this is a loop, not an answer
REQUEST_TIMEOUT = 120     # seconds; closes the socket so the SERVER stops generating


def make_llm(ChatOllama, model, temperature=0, num_predict=NUM_PREDICT,
             timeout=REQUEST_TIMEOUT, **kw):
    """Build a capped ChatOllama.

    Takes the class rather than importing it, because the adapters import langchain lazily
    (they chdir into their target first) and this module must stay import-cheap.
    """
    return ChatOllama(model=model, temperature=temperature,
                      num_predict=num_predict, client_kwargs={"timeout": timeout}, **kw)
