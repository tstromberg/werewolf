//! sh-shim is not a shell. It runs `sh -c COMMAND` for programs that
//! insist on one, supercronic among them, in an image that has none: it
//! splits COMMAND into words as sh would and execs the first, and refuses
//! anything else sh would read specially. See README.md.

const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

/// max_command is the longest argument Linux passes with 4 KiB pages
/// (MAX_ARG_STRLEN), so the buffers below fit any COMMAND; split refuses
/// a longer one.
const max_command = 32 * 4096;
const default_path = "/usr/sbin:/usr/bin:/sbin:/bin";
/// refused is what sh reads specially outside quotes, besides control
/// characters.
const refused = "|&;<>()$`\\*?[]~#";

/// sh_words are first words sh never looks for on PATH: POSIX's reserved
/// words, those it lets a shell reserve, its special built-ins, and its
/// intrinsic utilities, which act on the shell itself.
const sh_words = [_][]const u8{
    "!",      "{",       "}",        "case",   "do",       "done",      "elif",
    "else",   "esac",    "fi",       "for",    "if",       "in",        "then",
    "until",  "while",   "[[",       "]]",     "function", "namespace", "select",
    "time",   ".",       ":",        "break",  "continue", "eval",      "exec",
    "exit",   "export",  "readonly", "return", "set",      "shift",     "times",
    "trap",   "unset",   "alias",    "bg",     "cd",       "command",   "fc",
    "fg",     "getopts", "hash",     "jobs",   "kill",     "read",      "type",
    "ulimit", "umask",   "unalias",  "wait",
};

var words: [max_command + 1]u8 = undefined;
var argv: [max_command / 2 + 2]?[*:0]const u8 = undefined;

pub fn main(init: std.process.Init.Minimal) void {
    // Set-user-ID, or with capabilities gained on exec, PATH and the
    // command are a less privileged caller's.
    if (linux.getauxval(std.elf.AT.SECURE) != 0) {
        say("refused: run set-user-ID, set-group-ID or with gained capabilities", .{});
        std.process.exit(126);
    }
    const command = switch (called(init.args.vector)) {
        .command => |c| c,
        .no_command => {
            say("not a shell: it runs only sh -c COMMAND, never commands from input", .{});
            std.process.exit(1);
        },
        .script => |s| {
            say("not a shell: it runs no script, and was given {s}", .{s[0..@min(s.len, 256)]});
            std.process.exit(1);
        },
        .option => |o| {
            say("not a shell: it takes no option {s}, only -c", .{o[0..@min(o.len, 32)]});
            std.process.exit(1);
        },
    };
    var bad: Bad = .{};
    const n = split(command, &words, &argv, &bad) catch {
        const byte = [1]u8{bad.byte};
        switch (bad.why) {
            .syntax => say(
                "refused: unquoted {s} is shell syntax; sh-shim runs one program",
                .{&byte},
            ),
            .control => say("refused: an unquoted control character, 0x{x:0>2}", .{bad.byte}),
            .expansion => say(
                "refused: {s} inside double quotes; sh-shim expands nothing",
                .{&byte},
            ),
            .assignment => say("refused: the first word is an assignment, NAME=...", .{}),
            .sh_word => say("refused: {s} is sh's own, not a program", .{bad.word}),
            .unterminated => say("refused: an unterminated {s} quote", .{&byte}),
            .too_long => say("refused: the command is too long", .{}),
        }
        std.process.exit(126);
    };
    if (n == 0) std.process.exit(0); // as sh -c '' does
    const env = init.environ.block.slice;
    const path = for (env) |e| {
        const s = std.mem.span(e.?);
        if (std.mem.startsWith(u8, s, "PATH=")) break s["PATH=".len..];
    } else default_path;
    run(argv[0..n :null], env.ptr, path);
}

/// Call is how sh-shim was called: with a COMMAND to run, or not as sh -c.
const Call = union(enum) {
    command: []const u8,
    /// sh alone, or -c with nothing after: sh would read its input.
    no_command,
    /// sh FILE, as the kernel runs a #!/bin/sh script.
    script: []const u8,
    /// An option but -c, or one after it.
    option: []const u8,
};

/// called reads args as sh would, accepting only `-c [--] COMMAND [NAME
/// [ARG...]]`. The words after COMMAND would be sh's $0, $1...; nothing
/// expands them.
fn called(args: []const [*:0]const u8) Call {
    if (args.len < 2) return .no_command;
    const first = std.mem.span(args[1]);
    if (!std.mem.eql(u8, first, "-c")) {
        if (first.len > 0 and (first[0] == '-' or first[0] == '+')) return .{ .option = first };
        return .{ .script = first };
    }
    const dashes = args.len > 2 and std.mem.eql(u8, std.mem.span(args[2]), "--");
    const at: usize = if (dashes) 3 else 2;
    if (args.len <= at) return .no_command;
    const command = std.mem.span(args[at]);
    // Without --, sh takes a leading - or + as more options.
    if (!dashes and command.len > 0 and (command[0] == '-' or command[0] == '+'))
        return .{ .option = command };
    return .{ .command = command };
}

/// run execs argv[0] with the environment unchanged, as sh would: a name
/// with a slash is a path, any other is looked for along path. It returns
/// only by exiting with sh's status: 127 when there is no such program,
/// 126 when there is one but it cannot be run.
fn run(
    a: [:null]const ?[*:0]const u8,
    envp: [*:null]const ?[*:0]const u8,
    path: []const u8,
) noreturn {
    const name = std.mem.span(a[0].?);
    if (name.len == 0) fail(name, .NOENT);
    if (std.mem.findScalar(u8, name, '/') != null)
        fail(name, linux.errno(linux.execve(a[0].?, a.ptr, envp)));
    var denied = false;
    var buf: [4096]u8 = undefined;
    var search: Search = .{ .dirs = std.mem.splitScalar(u8, path, ':'), .name = name };
    while (search.next(&buf)) |p| switch (linux.errno(linux.execve(p, a.ptr, envp))) {
        .NOENT, .NOTDIR => {},
        .ACCES => denied = true,
        else => |e| fail(name, e),
    };
    fail(name, if (denied) .ACCES else .NOENT);
}

/// fail says why name did not run and exits with sh's status for it.
fn fail(name: []const u8, e: linux.E) noreturn {
    const shown = name[0..@min(name.len, 256)];
    switch (e) {
        .NOENT, .NOTDIR => say("{s}: not found", .{shown}),
        .ACCES => say("{s}: permission denied", .{shown}),
        .NOEXEC => say("{s}: not a program, and sh-shim runs no scripts", .{shown}),
        else => say("{s}: cannot run it: {t}", .{ shown, e }),
    }
    std.process.exit(if (e == .NOENT or e == .NOTDIR) 127 else 126);
}

/// say writes one line to stderr. A name in it can come from anyone's
/// input, so control characters show as ?.
fn say(comptime fmt: []const u8, args: anytype) void {
    var line: [512]u8 = undefined;
    const s = std.mem.print(line[0 .. line.len - 1], "sh-shim: " ++ fmt, args) catch return;
    for (s) |*b| if (b.* < ' ' or b.* == 0x7f) {
        b.* = '?';
    };
    line[s.len] = '\n';
    _ = linux.write(2, &line, s.len + 1);
}

/// Search yields where sh looks for a program name without a slash: in each
/// directory of PATH in turn. Unlike sh, it skips an empty or relative
/// entry, so a program is never found in whatever directory a job runs in.
const Search = struct {
    dirs: std.mem.SplitIterator(u8, .scalar),
    name: []const u8,

    /// next returns the next place to try, written to buf, skipping one too
    /// long for it, or null when there are no more.
    fn next(s: *Search, buf: []u8) ?[:0]const u8 {
        while (s.dirs.next()) |dir| {
            if (dir.len == 0 or dir[0] != '/') continue;
            return std.mem.printSentinel(buf, "{s}/{s}", .{ dir, s.name }, 0) catch continue;
        }
        return null;
    }
};

/// Why says why split refused a command.
const Why = enum { syntax, control, expansion, assignment, sh_word, unterminated, too_long };

/// Bad is why split refused a command, and the byte or first word at fault.
const Bad = struct { why: Why = .syntax, byte: u8 = 0, word: []const u8 = "" };

/// split breaks command into words as sh would: on blanks, with single and
/// double quotes grouping a word literally, as many pieces of one word as
/// touch. It writes each word, NUL-terminated, to buf, points out at each,
/// ends out with null, and returns how many words there are. It refuses
/// what sh would read specially: a byte of refused or a control character
/// but tab outside quotes; $, a backtick or a backslash inside double
/// quotes; an assignment or one of sh_words, however quoted, as the first
/// word; an unterminated quote; and a command too long for buf and out.
fn split(command: []const u8, buf: []u8, out: []?[*:0]const u8, bad: *Bad) error{Refused}!usize {
    // A word takes a byte, or two for '', and a blank to end it, so n words
    // need n + 1 slots and at most command.len + 1 bytes.
    if (buf.len < command.len + 1 or out.len < command.len / 2 + 2)
        return refuse(bad, .too_long, 0);
    var n: usize = 0; // words ended
    var o: usize = 0; // bytes written to buf
    var start: usize = 0; // where the word being read starts in buf
    var in_word = false;
    var quoted = false; // the word being read has a quote in it
    var i: usize = 0;
    while (true) : (i += 1) {
        if (i == command.len or command[i] == ' ' or command[i] == '\t') {
            if (in_word) {
                buf[o] = 0;
                out[n] = buf[start..o :0];
                n += 1;
                o += 1;
                start = o;
                in_word = false;
                quoted = false;
            }
            if (i == command.len) break;
            continue;
        }
        const c = command[i];
        if (c == '\'' or c == '"') {
            const close = std.mem.findScalarPos(u8, command, i + 1, c) orelse
                return refuse(bad, .unterminated, c);
            const text = command[i + 1 .. close];
            if (c == '"') if (std.mem.findAny(u8, text, "$`\\")) |at|
                return refuse(bad, .expansion, text[at]);
            @memcpy(buf[o..][0..text.len], text);
            o += text.len;
            i = close;
            quoted = true;
        } else {
            if (c < ' ' or c == 0x7f) return refuse(bad, .control, c);
            if (std.mem.findScalar(u8, refused, c) != null) return refuse(bad, .syntax, c);
            // sh takes NAME= opening the first word, unquoted, as an assignment.
            if (c == '=' and n == 0 and !quoted) {
                const name = buf[start..o];
                const assigns = name.len > 0 and !std.ascii.isDigit(name[0]) and for (name) |b| {
                    if (!std.ascii.isAlphanumeric(b) and b != '_') break false;
                } else true;
                if (assigns) return refuse(bad, .assignment, c);
            }
            buf[o] = c;
            o += 1;
        }
        in_word = true;
    }
    out[n] = null;
    if (n > 0) for (sh_words) |w| if (std.mem.eql(u8, std.mem.span(out[0].?), w)) {
        bad.* = .{ .why = .sh_word, .word = w };
        return error.Refused;
    };
    return n;
}

fn refuse(bad: *Bad, why: Why, byte: u8) error{Refused} {
    bad.* = .{ .why = why, .byte = byte };
    return error.Refused;
}

const testing = std.testing;

/// expectWords checks that split gives command exactly want.
fn expectWords(command: []const u8, want: []const []const u8) !void {
    var buf: [256]u8 = undefined;
    var out: [130]?[*:0]const u8 = undefined;
    var bad: Bad = .{};
    const n = try split(command, &buf, &out, &bad);
    try testing.expectEqual(want.len, n);
    for (want, out[0..n]) |w, got| try testing.expectEqualStrings(w, std.mem.span(got.?));
    try testing.expectEqual(null, out[n]);
}

/// expectRefused checks that split refuses command for why, at byte.
fn expectRefused(command: []const u8, why: Why, byte: u8) !void {
    var buf: [256]u8 = undefined;
    var out: [130]?[*:0]const u8 = undefined;
    var bad: Bad = .{};
    try testing.expectError(error.Refused, split(command, &buf, &out, &bad));
    try testing.expectEqual(why, bad.why);
    try testing.expectEqual(byte, bad.byte);
}

test "split: words on blanks" {
    try expectWords("/usr/bin/tootctl media remove --days 7", &.{
        "/usr/bin/tootctl", "media", "remove", "--days", "7",
    });
    try expectWords("  a\t\tb  c\t", &.{ "a", "b", "c" });
    try expectWords("ruby -e 1 x=y", &.{ "ruby", "-e", "1", "x=y" });
    try expectWords(
        "{a,b} ! % + , . : @ ^ }",
        &.{ "{a,b}", "!", "%", "+", ",", ".", ":", "@", "^", "}" },
    );
    try expectWords("a\x80b \xc3\xa9", &.{ "a\x80b", "\xc3\xa9" });
}

test "split: quotes group a word literally" {
    try expectWords("echo 'a b' \"c d\"", &.{ "echo", "a b", "c d" });
    try expectWords("x a'b c'd\"e f\"g", &.{ "x", "ab cde fg" });
    try expectWords("x '' \"\" a''b", &.{ "x", "", "", "ab" });
    try expectWords("''", &.{""});
    // Inside single quotes everything is literal, and inside double quotes
    // all but $, backtick and backslash.
    try expectWords(
        "x '|&;<>()$`\\*?[]~#' \"|&;<>()*?[]~#'\"",
        &.{ "x", "|&;<>()$`\\*?[]~#", "|&;<>()*?[]~#'" },
    );
    try expectWords("x 'a\nb' \"c\td\"", &.{ "x", "a\nb", "c\td" });
}

test "split: an empty or blank command has no words" {
    try expectWords("", &.{});
    try expectWords("   ", &.{});
    try expectWords("\t \t", &.{});
}

test "split refuses each byte sh reads specially outside quotes" {
    for (refused) |c| {
        var cmd: [16]u8 = undefined;
        try expectRefused(&.{c}, .syntax, c);
        try expectRefused(std.mem.print(&cmd, "a {c}", .{c}) catch unreachable, .syntax, c);
        try expectRefused(std.mem.print(&cmd, "a b{c}c", .{c}) catch unreachable, .syntax, c);
        try expectRefused(std.mem.print(&cmd, "a 'b'{c}", .{c}) catch unreachable, .syntax, c);
    }
    try expectRefused("job | logger", .syntax, '|');
    try expectRefused("job >/tmp/out 2>&1", .syntax, '>');
    try expectRefused("job # nightly", .syntax, '#');
}

test "split refuses an unquoted control character but tab, and keeps a quoted one" {
    // From 1: no argument holds a NUL.
    for (1..0x80) |b| {
        const c: u8 = @intCast(b);
        if (c == '\t' or (c >= ' ' and c != 0x7f)) continue;
        var cmd: [16]u8 = undefined;
        try expectRefused(&.{c}, .control, c);
        try expectRefused(std.mem.print(&cmd, "a b{c}c", .{c}) catch unreachable, .control, c);
        try expectRefused(std.mem.print(&cmd, "a 'b'{c}", .{c}) catch unreachable, .control, c);
        try expectWords(std.mem.print(&cmd, "a '{c}' \"{c}\"", .{ c, c }) catch unreachable, &.{
            "a", &.{c}, &.{c},
        });
    }
    try expectRefused("a\nb", .control, '\n');
    try expectRefused("job\r", .control, '\r');
    try expectRefused("a\x00", .control, 0);
}

test "split refuses sh's own words as the first word, however quoted" {
    for (sh_words) |w| {
        var cmd: [32]u8 = undefined;
        var buf: [64]u8 = undefined;
        var out: [32]?[*:0]const u8 = undefined;
        var bad: Bad = .{};
        // Unquoted, [[ and ]] are refused sooner, as globs.
        const plain = std.mem.findAny(u8, w, refused) == null;
        inline for (.{
            "'{s}' x",
            "\"{s}\"",
            "{s}",
            "  {s} x",
        }, 0..) |shape, i| if (i < 2 or plain) {
            const c = try std.mem.print(&cmd, shape, .{w});
            try testing.expectError(error.Refused, split(c, &buf, &out, &bad));
            try testing.expectEqual(.sh_word, bad.why);
            try testing.expectEqualStrings(w, bad.word);
        };
        try expectWords(try std.mem.print(&cmd, "x '{s}'", .{w}), &.{ "x", w });
    }
    // Only the whole word: these are programs.
    try expectWords("exec2 x", &.{ "exec2", "x" });
    try expectWords("ifx", &.{"ifx"});
    try expectWords("test -f x", &.{ "test", "-f", "x" });
    try expectWords("true", &.{"true"});
}

test "split refuses $, backtick and backslash inside double quotes" {
    try expectRefused("echo \"$HOME\"", .expansion, '$');
    try expectRefused("echo \"`id`\"", .expansion, '`');
    try expectRefused("echo \"a\\\"", .expansion, '\\');
    try expectWords("echo '$HOME' '`id`' '\\'", &.{ "echo", "$HOME", "`id`", "\\" });
}

test "split refuses an assignment as the first word" {
    try expectRefused("A=1 job", .assignment, '=');
    try expectRefused("_x9=1", .assignment, '=');
    try expectRefused("A=", .assignment, '=');
    try expectRefused("A=\"b c\" job", .assignment, '=');
    try expectRefused("  path=/x job", .assignment, '=');
    // Not assignments: a later word, a quoted name, a quoted =, no name.
    try expectWords("job A=1", &.{ "job", "A=1" });
    try expectWords("'A'=1", &.{"A=1"});
    try expectWords("A'=1'", &.{"A=1"});
    try expectWords("1A=x", &.{"1A=x"});
    try expectWords("a-b=c", &.{"a-b=c"});
    try expectWords("=x", &.{"=x"});
}

test "split refuses an unterminated quote" {
    try expectRefused("'a", .unterminated, '\'');
    try expectRefused("a \"b", .unterminated, '"');
    try expectRefused("'a'\"", .unterminated, '"');
    try expectRefused("\"a'", .unterminated, '"');
}

test "split: buffers of exactly the size it asks for, and too small" {
    var buf: [10]u8 = undefined;
    var out: [6]?[*:0]const u8 = undefined;
    var bad: Bad = .{};
    // Nine bytes: five one-byte words, or three empty quoted ones.
    try testing.expectEqual(5, try split("a b c d e", &buf, &out, &bad));
    try testing.expectEqual(3, try split("'' '' ''", &buf, &out, &bad));
    try testing.expectEqual(1, try split("'abcdefg'", &buf, &out, &bad));
    try testing.expectError(error.Refused, split("abcdefghij", &buf, &out, &bad));
    try testing.expectEqual(.too_long, bad.why);
    try testing.expectError(error.Refused, split("a b c d e", &buf, out[0..5], &bad));
}

test Search {
    var buf: [32]u8 = undefined;
    const long: [30]u8 = @splat('/');
    var s: Search = .{
        .dirs = std.mem.splitScalar(u8, "/a::.:bin:/b/:./c:" ++ long, ':'),
        .name = "x",
    };
    try testing.expectEqualStrings("/a/x", s.next(&buf).?);
    try testing.expectEqualStrings("/b//x", s.next(&buf).?);
    try testing.expectEqual(null, s.next(&buf)); // the last is too long for buf
    s = .{ .dirs = std.mem.splitScalar(u8, "", ':'), .name = "x" };
    try testing.expectEqual(null, s.next(&buf));
    s = .{ .dirs = std.mem.splitScalar(u8, default_path, ':'), .name = "supercronic" };
    for ([_][]const u8{ "/usr/sbin", "/usr/bin", "/sbin", "/bin" }) |dir| {
        const p = s.next(&buf).?;
        try testing.expect(std.mem.startsWith(u8, p, dir) and
            std.mem.endsWith(u8, p, "/supercronic"));
    }
    try testing.expectEqual(null, s.next(&buf));
}

test called {
    try testing.expectEqualDeep(Call{ .command = "a b" }, called(&.{ "sh", "-c", "a b" }));
    try testing.expectEqualDeep(Call{ .command = "a" }, called(&.{ "sh", "-c", "a", "name", "1" }));
    // glibc's and musl's system and popen pass --, for a command led by -.
    try testing.expectEqualDeep(Call{ .command = "a" }, called(&.{ "sh", "-c", "--", "a" }));
    try testing.expectEqualDeep(Call{ .command = "-a" }, called(&.{ "sh", "-c", "--", "-a" }));
    try testing.expectEqualDeep(Call{ .command = "--" }, called(&.{ "sh", "-c", "--", "--" }));
    try testing.expectEqualDeep(Call{ .command = "" }, called(&.{ "sh", "-c", "" }));
    try testing.expectEqualDeep(@as(Call, .no_command), called(&.{}));
    try testing.expectEqualDeep(@as(Call, .no_command), called(&.{"-sh"}));
    try testing.expectEqualDeep(@as(Call, .no_command), called(&.{ "sh", "-c" }));
    try testing.expectEqualDeep(@as(Call, .no_command), called(&.{ "sh", "-c", "--" }));
    try testing.expectEqualDeep(
        Call{ .script = "/etc/x.sh" },
        called(&.{ "sh", "/etc/x.sh", "a" }),
    );
    try testing.expectEqualDeep(Call{ .script = "" }, called(&.{ "sh", "" }));
    for ([_][]const [*:0]const u8{
        &.{ "sh", "-s" },
        &.{ "sh", "-i" },
        &.{ "sh", "-ec", "a" },
        &.{ "sh", "-e", "-c", "a" },
        &.{ "sh", "+x", "a" },
        &.{ "sh", "--", "a" },
        &.{ "sh", "-c", "-e", "a" },
        &.{ "sh", "-c", "+e", "a" },
        &.{ "sh", "-c", "-" },
    }) |args| switch (called(args)) {
        .option => {},
        else => |got| {
            std.debug.print("{any}: {any}\n", .{ args, got });
            return error.TestUnexpectedResult;
        },
    };
}

/// randomCommand fills buf with up to 24 bytes, most of them a shell's
/// interesting ones. Braces are left out: bash, /bin/sh on some hosts,
/// expands {a,b}, which POSIX sh and sh-shim do not.
fn randomCommand(r: std.Random, buf: *[24]u8) []const u8 {
    const alphabet = "ab/-=_. \t\t  ''\"\"\n" ++ refused;
    const len = r.uintLessThan(usize, buf.len + 1);
    for (buf[0..len]) |*b| b.* = alphabet[r.uintLessThan(usize, alphabet.len)];
    return buf[0..len];
}

test "random commands: the words /bin/sh gives" {
    Io.Dir.cwd().access(testing.io, "/bin/sh", .{}) catch return error.SkipZigTest;
    const gpa = testing.allocator;
    // A function prints each of its arguments and a NUL, then \001 and a
    // NUL to end the record; the script calls it with each accepted command.
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try script.appendSlice(
        gpa,
        "p() { for a; do printf '%s\\0' \"$a\"; done; printf '\\001\\0'; }\n",
    );
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(0x6e6f74617368);
    var cmd: [24]u8 = undefined;
    var buf: [25]u8 = undefined;
    var out: [14]?[*:0]const u8 = undefined;
    var bad: Bad = .{};
    var compared: usize = 0;
    var tried: usize = 0;
    while (compared < 2000) : (tried += 1) {
        const c = randomCommand(prng.random(), &cmd);
        const n = split(c, &buf, &out, &bad) catch continue;
        try script.print(gpa, "p {s}\n", .{c});
        for (out[0..n]) |w| try want.print(gpa, "{s}\x00", .{std.mem.span(w.?)});
        try want.appendSlice(gpa, "\x01\x00");
        compared += 1;
    }
    // The generator makes both accepted and refused commands.
    try testing.expect(tried > 3000);
    const r = try std.process.run(
        gpa,
        testing.io,
        .{ .argv = &.{ "/bin/sh", "-c", script.items } },
    );
    defer gpa.free(r.stdout);
    defer gpa.free(r.stderr);
    try testing.expectEqualStrings("", r.stderr);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, r.term);
    try testing.expectEqualSlices(u8, want.items, r.stdout);
}

test "random bytes: never a crash, and words within the bytes given" {
    var prng: std.Random.DefaultPrng = .init(0x636f6d6d616e64);
    const r = prng.random();
    var cmd: [40]u8 = undefined;
    var buf: [41]u8 = undefined;
    var out: [22]?[*:0]const u8 = undefined;
    var bad: Bad = .{};
    var accepted: usize = 0;
    for (0..100_000) |_| {
        const len = r.uintLessThan(usize, cmd.len + 1);
        // No NUL, which no argument holds.
        for (cmd[0..len]) |*b| b.* = if (r.boolean())
            r.intRangeAtMost(u8, 1, 255)
        else
            " '\"a"[r.uintLessThan(usize, 4)];
        const n = split(cmd[0..len], &buf, &out, &bad) catch continue;
        accepted += 1;
        var bytes: usize = 0;
        for (out[0..n]) |w| bytes += std.mem.span(w.?).len + 1;
        try testing.expect(bytes <= len + 1 and n <= (len + 1) / 2);
    }
    try testing.expect(accepted > 1000);
}
