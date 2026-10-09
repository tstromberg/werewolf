//! gitea-hook runs Gitea's git server hooks without a shell.
//!
//!     /usr/lib/werewolf/gitea-hooks/pre-receive [ARG...]
//!
//! Gitea writes each repository's hooks as bash scripts, and werewolf has no
//! bash. The gitea form points git's core.hooksPath at a directory of links
//! to this program, which execs `gitea --config /etc/gitea/app.ini hook NAME
//! ARG...` for the hook named by argv[0], keeping git's stdio and environment.

const std = @import("std");
const linux = std.os.linux;

const gitea = "/usr/bin/gitea";
const config = "/etc/gitea/app.ini";
const hooks = [_][:0]const u8{ "pre-receive", "update", "post-receive", "proc-receive" };
const max_args = 16;

pub fn main(init: std.process.Init.Minimal) void {
    const argv = init.args.vector;
    if (argv.len == 0 or argv.len > max_args) die("usage: HOOK [ARG...], as git runs it");
    // Pass the table's name, not argv[0]'s basename: the basename is not
    // NUL-terminated where it ends, so ".../pre-receive/" would pass the
    // check and reach Gitea with the slash.
    const name = std.fs.path.basename(std.mem.span(argv[0]));
    const hook = for (hooks) |h| {
        if (std.mem.eql(u8, name, h)) break h;
    } else die("not a hook Gitea has");

    var args: [max_args + 5:null]?[*:0]const u8 = @splat(null);
    args[0] = gitea;
    args[1] = "--config";
    args[2] = config;
    args[3] = "hook";
    args[4] = hook.ptr;
    for (argv[1..], 5..) |a, i| args[i] = a;
    const envp: [*:null]const ?[*:0]const u8 = @ptrCast(init.environ.block.slice.ptr);
    _ = linux.execve(gitea, &args, envp);
    die("cannot run " ++ gitea);
}

fn die(why: []const u8) noreturn {
    _ = linux.write(2, "gitea-hook: ", 12);
    _ = linux.write(2, why.ptr, why.len);
    _ = linux.write(2, "\n", 1);
    linux.exit_group(1);
}
