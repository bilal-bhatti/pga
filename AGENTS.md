---
type: Reference
scope: Project-level rules and the LLM doc-collaboration contract for this knowledge base.
authoritative-for:
  - project-collaboration-contract
status: active
last-reviewed: 2026-11-11
derived-from: []
---

# pga

_Replace this line with a one-sentence description of this knowledge base._

## Doc System

Doc work is governed by the shared `_contract` and the per-operation procedures (`doc-add`, `doc-update`, `doc-audit`, `doc-split`, `doc-remove`), all rendered by `cura prompt <name>` and injected into the `/doc-*` slash commands in `.claude/commands/`. The slash commands are the formal entry points; the rules apply equally to natural-language doc requests. To read the contract or a procedure directly, run `cura prompt _contract` (or any name). Map by intent, not syntax:

| User intent signal | Procedure to apply |
|---|---|
| "add to X", "update X with Y", "spec says Z now" | `doc-update` |
| "write a spec for X", "plan for Y", "ADR for Z" | `doc-add` |
| "we don't need X", "X is superseded by Y" | `doc-remove` |
| "X is too long", "split off section Y" | `doc-split` |
| "are the docs consistent?", "what's stale?" | `doc-audit` |
| "let's explore X" (no doc named) | Check for an authoritative home; extend (`doc-update`) if one exists, otherwise create (`doc-add`). Never invent a second home for an owned topic. |

Always-on contract pieces (apply whether or not a command was explicitly invoked):

- Every governed-doc edit checks `authoritative-for` first; if out of scope, redirect to the owner doc.
- Every fact is either owned by this doc (declared in its `authoritative-for`) or linked to its owner - never restated.
- Every change enumerates cross-references and propagates explicitly; never silently retarget or delete.
- Every LLM-derived doc populates `derived-from` with the actual sources read.
- Every edit stamps `last-reviewed`.
- Every doc declares a `type` - `Reference | Plan | Overview | Index`, and no other value. It is required and it blocks: a doc created without one fails the commit gate, and a doc touched without one gains one before it lands.
- Soft cap (400 lines) is a flag; hard cap (800 lines) is a stop.
- Refuse to bypass the authority rule "just for now." That's how rot starts.

## Governed Scope

Governed docs live under `docs/`. The full scope table and front-matter schema are in `_contract` §1; run `cura prompt _contract` to read them. The `cura` tool enforces the contract: `cura audit` for health checks, `cura check` for individual checks, and the `.cura/hooks/` hooks gate commits: `pre-commit` on structural defects, `commit-msg` on content this change drops without declaring a `Dropped:` trailer (`_contract` §6.8).

Some of the record lives in commit messages rather than in a doc, because intent is the one thing a diff cannot show: `Dropped:` (this loss was deliberate), `Propagated-from:` (this edit absorbed that source's change), `Demoted-to:` (this doc is no longer the source of truth for that referent). The rule governing them is in `_contract` §5; `cura trailers --keys` prints the three and what each claims, and `cura trailers [--since <ref>]` prints what this repo has actually declared.
