#!/bin/sh
# Puts the `peers` command on your PATH. Run it from a git clone of this repo;
# later, `peers update` pulls new versions into that same clone.
set -e
here="$(cd "$(dirname "$0")" && pwd)"

py="$(command -v python3 || true)"
[ -n "$py" ] || { echo "python3 not found. On macOS: xcode-select --install"; exit 1; }
"$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || { echo "python3 is older than 3.9; please install a newer one"; exit 1; }
command -v git >/dev/null || { echo "git not found"; exit 1; }

chmod +x "$here/peers.py"
mkdir -p "$HOME/.local/bin"
ln -sf "$here/peers.py" "$HOME/.local/bin/peers"
echo "installed: $("$HOME/.local/bin/peers" --version) -> $HOME/.local/bin/peers"

case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) echo "note: add this line to ~/.zshrc, then open a new terminal:"
     echo '  export PATH="$HOME/.local/bin:$PATH"' ;;
esac
if [ "$1" = "--setup" ]; then
  # guided setup for the project in the folder this was started from
  shift
  exec "$HOME/.local/bin/peers" setup "$@"
fi
echo "next, inside your project folder: peers setup"
