#!/usr/bin/env bash
# Resolve a Python 3 interpreter for the M3 tools.
#
# Hosted CI and the self-hosted builder always provide `python3`, but Git Bash
# on Windows ships the interpreter as `python` only. Sourcing this file sets
# PYTHON to a command that is confirmed to be Python 3, honouring an explicit
# PYTHON override first, and fails closed when nothing usable is found.

m3_is_python3() {
  # Compare reported output rather than only an exit status, so that a program
  # which ignores its arguments and exits successfully is not mistaken for an
  # interpreter.
  local reported
  reported=$("$1" -c 'import sys; print(sys.version_info[0])' 2>/dev/null) || return 1
  # A Windows interpreter prints CRLF; do not depend on the shell stripping it.
  [[ ${reported%$'\r'} == 3 ]]
}

m3_resolve_python() {
  local candidate

  if [[ -n "${PYTHON:-}" ]]; then
    if m3_is_python3 "$PYTHON"; then
      return 0
    fi
    echo "PYTHON=$PYTHON is not a usable Python 3 interpreter" >&2
    return 1
  fi

  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && m3_is_python3 "$candidate"; then
      PYTHON=$candidate
      return 0
    fi
  done

  echo 'no Python 3 interpreter found; set PYTHON=/path/to/python3' >&2
  return 1
}
