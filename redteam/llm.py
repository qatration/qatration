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


def chat_ollama():
    """`ChatOllama`, or a refusal that names the install rather than the import.

    `langchain-ollama` is optional by design: it belongs to the practice fleet and the adaptive
    attacker, and somebody testing their own endpoint never imports it. Optional by design has
    to fail by design too — eight modules imported it bare, so the answer to installing the
    base package and reaching for a practice bot was

        ModuleNotFoundError: No module named 'langchain_ollama'

    which names an import when the reader needs an install. It is declared in the `[fleet]`
    extra and the README says so; a traceback does not.

    Imported HERE and not at module scope, for the reason `make_llm` gives about itself: the
    adapters chdir into their target before touching langchain, so this module has to stay
    cheap to import. Calling it is what pays.
    """
    try:
        from langchain_ollama import ChatOllama
    except ImportError as e:
        raise SystemExit(
            "this needs langchain-ollama, which the base install deliberately leaves out: it "
            "belongs to the practice fleet and the adaptive attacker, and testing your own "
            "endpoint never touches it.\n"
            "    pip install \"qatration[fleet]\"\n"
            f"  (the import said: {e})")
    return ChatOllama


def make_llm(ChatOllama, model, temperature=0, num_predict=NUM_PREDICT,
             timeout=REQUEST_TIMEOUT, **kw):
    """Build a capped ChatOllama.

    Takes the class rather than importing it, because the adapters import langchain lazily
    (they chdir into their target first) and this module must stay import-cheap.
    """
    return ChatOllama(model=model, temperature=temperature,
                      num_predict=num_predict, client_kwargs={"timeout": timeout}, **kw)
