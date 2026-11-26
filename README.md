# peers

For people who work on a project together, each with their own Claude Code.

- **See each other's sessions.** You choose which of your Claude Code sessions are
  shared. A filtered copy of each transcript is kept in the folder `peers/` of the
  project's git repo. Whoever can open the repo can read it, and so can their Claude.
- **Keep the repo itself in sync.** Once a minute the tool looks at the repo. If
  anything changed, a session record or any other file, it commits the change to
  the repo's branch, takes in what others pushed, and pushes. No change, no commit.
- **Message each other's sessions.** A collaborator's Claude can send a question to
  one of your shared sessions and get the answer back. By default every message
  waits for your approval.

It is a command-line tool with a background sync, a Claude Code skill (`/peers`)
so you can simply ask Claude, and a pop-up for approving messages.

## Start

You own the project (run this inside the project folder):

```bash
git clone https://github.com/Xiaoyu-Ouyang/peers.git ~/.peers/src && sh ~/.peers/src/install.sh --setup
```

It asks your name and which existing sessions to share, then shares new sessions
started in that folder automatically, starts the background sync and installs the skill.

You want to follow someone else's project (they have run the step above and gave
you access to the repo):

```bash
git clone https://github.com/Xiaoyu-Ouyang/peers.git ~/.peers/src && sh ~/.peers/src/install.sh
```

```bash
peers init --me yourname
```

```bash
peers follow git@github.com:THEM/their-project.git
```

Their files land in `~/peers/their-project/code`, their shared sessions in
`~/peers/their-project/sessions`, and both stay current. `peers invite` prints
these lines with the right addresses filled in.

Needs macOS or Linux, git, Python 3.9+ (the one shipped with macOS works). The
background service and the approval pop-up are macOS only for now.

## Everyday use

In Claude Code, ask in plain words ("what is Alex's session doing?", "share
this session", "ask Alex's session which parameters it used") or type `/peers`.
The commands underneath:

| | |
|---|---|
| `peers status` | who you are, your spaces, where the mirrors are, what waits for you |
| `peers ls` | your recent sessions and which are shared |
| `peers share <session>` / `peers unshare <session>` | `<session>` is `current`, the start of an id, or part of a title |
| `peers space auto <space> on\|off` | share sessions started in the project folder automatically |
| `peers live on\|off\|plan\|status <space>` | push working files to the branch `live/<you>` every minute |
| `peers who` | sessions others share with you, as addresses |
| `peers send <name>/<session> "text"` | message a collaborator's session |
| `peers reply <id> "text"` | answer a message that was delivered to this session |
| `peers inbox` / `peers outbox` | messages to you / from you, with their state and answers |
| `peers approve <id>` / `peers deny <id>` | decide on a waiting message (person only) |
| `peers inbound <session> ask\|replies\|auto\|off` | who may message a session (person only) |
| `peers update` | get the latest version |

## What collaborators see of a shared session

Included: your messages and Claude's replies in full; one line per tool call (the
command, file path or search pattern); tool output cut to 2,000 characters; the
session's title, state and last activity. Sharing covers the session from its
first message, not from the moment you share it.

Never included: Claude's thinking; images; output of connector (MCP) tools, which
can hold mail, chat or web pages; the content of files read from outside the
project folders (the path is shown). A session that runs outside the project
folders is shared without any tool output unless you pass `--outputs on`.

Folders that hold other people's words (a chat archive, private notes) should be
marked private: `peers space private <space> <folder>`. Output of any tool call
that mentions such a folder is then left out. `--pattern REGEX` does the same for
output whose text matches, for example the line format a chat watcher prints.
Claude's own replies are never filtered, so a reply that quotes a chat still shows.

Strings that look like keys, tokens or passwords are replaced by `[REDACTED]`.
That catches known formats only. Shell output is otherwise mirrored as printed, so
do not share a session that printed something private. Unsharing removes a session
from the current version of the mirror; copies others already pulled, and the
repo's history, keep what was sent.

## What it does to your repo

After `peers setup`, the background sync runs this once a minute, and only when
something changed:

1. writes your shared session records into `peers/<you>/`;
2. commits every changed file of the repo (records included) to the branch you
   are on, as `peers: <you> auto-sync`;
3. takes in what others pushed (`git pull --rebase`), then pushes.

It respects `.gitignore` and leaves out files larger than 20 MB, files that look
like credentials (`.env`, `*.pem`, `*.key` and similar), system and cache files
(`.DS_Store`, `__pycache__`), and folders marked private. `peers status` lists
what was left out.

Things to know:

- Unfinished work goes into the branch's history as you make it, and stays there.
- People who change different files never notice each other. If two people change
  the same file, the tool stops for that repo, shows a notification, and touches
  nothing; combine the two versions by hand (`git pull --rebase`) and it continues.
- It waits while you are on another branch, in the middle of a rebase or merge,
  or while another git command is running.
- In a project you only follow (`peers follow`), the only thing ever committed
  from your side is your own `peers/<you>/` folder, which carries your messages.

## Separate branches instead

`peers setup --separate-branches` keeps the repo's own branch untouched: records
go to a branch `sessions`, and `peers live on <space>` pushes the working state
(your last commit plus everything not committed yet) once a minute to the branch
`live/<you>`. `peers space to-main <space>` switches such a space to the single
branch layout.

The same size and credential limits apply. `peers live plan <space>` shows what
would be pushed without pushing anything.

## Messages

- You can only message a session its owner shared. The sender is the folder the
  message arrived in, so it cannot be changed by editing the message.
- `ask` (default): the receiving person approves each message, in the pop-up or
  with `peers approve` in a terminal. `replies`: answers to that session's own
  messages arrive directly. `auto`: everything arrives directly, at most 6 an
  hour per sender. `off`: refused.
- Approving and changing these settings refuse to run inside Claude Code: they
  are decisions for the person.
- A delivered message tells the receiving Claude who sent it, that it is from a
  different person, and how to answer. Messages cannot approve permission prompts.
- Unapproved messages expire after a day. Messages are limited to 8,000 characters.
- Messages and answers are files in the mirror: everyone with access to the repo
  can read them, before and after approval. Approval controls whether a message
  is put in front of your session, not who can read it.
- Anyone who can push to the repo could write a message into another person's
  folder. Work with people you trust not to do that.

## Where the mirror lives

**The folder `peers/` of the project's own repo, on its own branch** (what
`peers setup` does). No new repo, no new branches, no new invitations.

**A dedicated branch of the project's own repo** (`--separate-branches`). The
branch `sessions` has no history in common with the code, and `main` is never touched.

**A separate private repo**, when the people who may see sessions differ from the
people who may see the code, or when a project spans several repos:

```bash
peers space add myproject --remote git@github.com:OWNER/myproject-sessions.git --project ~/Desktop/myproject
```

Add `--no-push` to look at the result locally first; `peers space publish <space>`
starts pushing. Add `--view-only` to read a space without ever pushing to it.

With separate branches or a separate repo, the mirror is still the folder `peers/`
in your project, but kept out of the project's git through `.git/info/exclude`.

## Update

```bash
peers update
```

Pulls the latest version, shows what changed, restarts the background sync and
refreshes the skill. `peers status` tells you when a collaborator runs a newer
version. Updates are never installed on their own: the tool runs with your
permissions, so you decide when new code starts running. To publish a change:
bump `__version__` in `peers.py`, commit, push.

## How it works

- Transcripts are read from `~/.claude/projects/<folder>/<session-id>.jsonl`.
  That format is internal to Claude Code; records the tool does not understand
  are skipped, and `peers status` reports how many.
- Messages are delivered by writing one line to the receiving session's local
  socket. That interface is not in Claude Code's public documentation and may
  change with a Claude Code update.
- Each person writes only under `<mirror>/<their-name>/`, so pushes never conflict.
- Settings: `~/.peers/config.json`. Progress: `~/.peers/state.json`. Messages
  received: `~/.peers/inbox.json`. Background log: `~/.peers/daemon.log`.
- Delay: the sender pushes within a minute of a change, the reader pulls within a
  minute (20 seconds each with separate branches).
