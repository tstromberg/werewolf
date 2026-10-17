//! APK version ordering, shared by package selection.
const std = @import("std");
const testing = std.testing;

// apk's version order, ported from apk-tools 2.14's src/version.c so no apk
// need run: {digit}{.digit}...{letter}{_suffix{#}}...{-r#}. A version is a
// series of tokens; the separator before each gives its kind, and kinds may
// only rise, with a few exceptions.
const Tok = enum(i8) {
    invalid = -1,
    digit_or_zero,
    digit,
    letter,
    suffix,
    suffix_no,
    revision_no,
    end,
};

const VersionReader = struct {
    s: []const u8,
    t: Tok = .digit,

    const pre_suffixes = [_][]const u8{ "alpha", "beta", "pre", "rc" };
    const post_suffixes = [_][]const u8{ "cvs", "svn", "git", "hg", "p" };

    /// next sets r.t to the next token's kind, from the separator before it.
    fn next(r: *VersionReader) void {
        const s = r.s;
        var n: Tok = .invalid;
        if (s.len == 0 or s[0] == 0) {
            n = .end;
        } else if ((r.t == .digit or r.t == .digit_or_zero) and std.ascii.isLower(s[0])) {
            n = .letter;
        } else if (r.t == .letter and std.ascii.isDigit(s[0])) {
            n = .digit;
        } else if (r.t == .suffix and std.ascii.isDigit(s[0])) {
            n = .suffix_no;
        } else {
            switch (s[0]) {
                '.' => n = .digit_or_zero,
                '_' => n = .suffix,
                '-' => if (s.len > 1 and s[1] == 'r') {
                    n = .revision_no;
                    r.s = r.s[1..];
                },
                else => {},
            }
            r.s = r.s[1..];
        }
        if (@backingInt(n) < @backingInt(r.t) and !((n == .digit_or_zero and r.t == .digit) or
            (n == .suffix and r.t == .suffix_no) or (n == .digit and r.t == .letter))) n = .invalid;
        r.t = n;
    }

    /// token returns the value of the token of kind r.t and moves past it.
    fn token(r: *VersionReader) i64 {
        const s = r.s;
        if (s.len == 0) {
            r.t = .end;
            return 0;
        }
        var i: usize = 0;
        var v: i64 = 0;
        var nt: Tok = .invalid;
        switch (r.t) {
            .digit_or_zero,
            .digit,
            .suffix_no,
            .revision_no,
            => if (r.t == .digit_or_zero and s[0] == '0') {
                // Leading zeros: 1.01 is older than 1.1.
                while (i + 1 < s.len and s[i + 1] == '0') i += 1;
                nt = .digit;
                v = -@as(i64, @intCast(i));
            } else {
                // Refuse more than 17 digits before they overflow: versions
                // come from untrusted input.
                while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) {
                    if (i == 17) return r.fail();
                    v = v * 10 + (s[i] - '0');
                }
            },
            .letter => {
                v = s[0];
                i = 1;
            },
            .suffix => suffix: {
                // Pre-release suffixes are negative (alpha -4 to rc -1);
                // post-release ones are not.
                for (pre_suffixes, 0..) |p, k| if (std.mem.startsWith(u8, s, p)) {
                    i = p.len;
                    v = @as(i64, @intCast(k)) - pre_suffixes.len;
                    break :suffix;
                };
                for (post_suffixes, 0..) |p, k| if (std.mem.startsWith(u8, s, p)) {
                    i = p.len;
                    v = @intCast(k);
                    break :suffix;
                };
                return r.fail();
            },
            else => return r.fail(),
        }
        r.s = s[i..];
        if (r.s.len == 0) {
            r.t = .end;
        } else if (nt != .invalid) {
            r.t = nt;
        } else {
            r.next();
        }
        return v;
    }

    fn fail(r: *VersionReader) i64 {
        r.t = .invalid;
        return std.math.minInt(i64);
    }
};

/// apkOrder compares a with b as `apk version -t a b` does.
pub fn order(a: []const u8, b: []const u8) std.math.Order {
    var x: VersionReader = .{ .s = a };
    var y: VersionReader = .{ .s = b };
    var xv: i64 = 0;
    var yv: i64 = 0;
    while (x.t == y.t and x.t != .end and x.t != .invalid and xv == yv) {
        xv = x.token();
        yv = y.token();
    }
    if (xv != yv) return std.math.order(xv, yv);
    if (x.t == y.t) return .eq;
    // Equal up to the shorter one: the longer is newer, unless it continues
    // with a pre-release suffix.
    var xs = x;
    var ys = y;
    if (x.t == .suffix and xs.token() < 0) return .lt;
    if (y.t == .suffix and ys.token() < 0) return .gt;
    return std.math.order(@backingInt(y.t), @backingInt(x.t));
}

/// validVersion reports whether apk would accept s as a version.
pub fn valid(s: []const u8) bool {
    var r: VersionReader = .{ .s = s };
    while (r.t != .end and r.t != .invalid) _ = r.token();
    return r.t == .end;
}

test order {
    // Each answer is from apk-tools 2.14.10's `apk version -t`.
    const cases = [_]struct { []const u8, []const u8, std.math.Order }{
        .{ "1.0", "1.0.1", .lt },
        .{ "1.0_alpha", "1.0", .lt },
        .{ "1.0_alpha1", "1.0_alpha2", .lt },
        .{ "1.0_beta", "1.0_alpha", .gt },
        .{ "1.0_rc1", "1.0", .lt },
        .{ "1.0_p1", "1.0", .gt },
        .{ "1.0-r1", "1.0-r0", .gt },
        .{ "1.0-r10", "1.0-r9", .gt },
        .{ "1.0a", "1.0", .gt },
        .{ "1.0a", "1.0b", .lt },
        .{ "1.01", "1.1", .lt },
        .{ "1.010", "1.9", .lt },
        .{ "1.001", "1.01", .lt },
        .{ "2.0", "1.99", .gt },
        .{ "1.3.2.1_rc20260601-r0", "1.3.2.1-r0", .lt },
        .{ "1.3.2.1_rc20260601-r0", "1.3.2-r5", .gt },
        .{ "4.0.3-r3", "4.0.2-r0", .gt },
        .{ "1.38.0-r2", "1.37.0-r30", .gt },
        .{ "1.0", "1.0", .eq },
        .{ "1.0-r0", "1.0", .gt },
        .{ "0", "1.0", .lt },
        .{ "1.0_git20260101", "1.0", .gt },
        .{ "1.0_cvs", "1.0_svn", .lt },
        .{ "6.18.55-r0", "6.18.9-r0", .gt },
        .{ "1.2.3_p4-r1", "1.2.3_p4-r0", .gt },
        .{ "1.2.3_pre1", "1.2.3_p1", .lt },
        .{ "2.39.4", "2.39.4_p0", .lt },
        .{ "1.0_bad", "1.0", .lt },
        .{ "1.0_bad", "1.0_alpha", .lt },
        .{ "1.0_bad", "1.0_rc", .lt },
        .{ "1.0.bad", "1.0.001", .gt },
        .{ "abc", "1.0", .lt },
        .{ "1.0.", "1.0", .gt },
        .{ "1.0", "1.0-r", .lt },
        .{ "1.2.3a1", "1.2.3a", .gt },
        .{ "5.2.37_p20250701-r0", "5.2.37-r40", .gt },
        .{ "2026.04.13-r1", "2026.4.13-r1", .lt },
        .{ "1.0.0.0.0.0", "1.0", .gt },
        .{ "1.0_alpha_p1", "1.0_alpha", .gt },
    };
    for (cases) |c| {
        errdefer std.debug.print("{s} {s}\n", .{ c[0], c[1] });
        try testing.expectEqual(c[2], order(c[0], c[1]));
        try testing.expectEqual(c[2].invert(), order(c[1], c[0]));
    }
    // Validity as `apk version -c` judged it.
    for ([_][]const u8{
        "1.0",
        "1.0.",
        "1.0-r",
        "0",
        "",
        "1.0_alpha_p1",
        "1.3.2.1_rc20260601-r0",
    }) |v| try testing.expect(valid(v));
    for ([_][]const u8{
        "1.0_bad",
        "abc",
        "1.0-x",
        "1.0 ",
        "1.0-r1a",
        "1234567890123456789",
    }) |v| try testing.expect(!valid(v));
}
