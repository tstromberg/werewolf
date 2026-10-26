//! The same real API workload for candidate boots and signed A/B transitions.
const std = @import("std");
const host = @import("host");

pub const health = "i=0; until wget -q -T 5 -O - http://127.0.0.1:49999/_/health | " ++
    "grep -q '\"status\":\"ok\"'; do i=$((i + 1)); [ $i -lt 180 ] || exit 1; sleep 5; done";
pub const tunnel = "wget -q -T 10 -O - http://127.0.0.1:2000/metrics | grep -q cloudflared";
const sample = "module.exports = function add(a, b) { return a + b; };\n";

/// The guest reads the token; no secret becomes a host argument or log entry.
/// Flush the seed before howl stop's power cut: postdoc's best-effort cache
/// uses atomic renames, which alone do not make new files durable on disk.
pub fn command(gpa: std.mem.Allocator, resumed: bool) ![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(sample, &digest, .{});
    const request = if (resumed)
        try gpa.print("wget -q -T 60 -O - --header \"Authorization: Bearer $t\" " ++
            "'http://127.0.0.1:49999/v1/lookup?sha256={s}'", .{std.fmt.bytesToHex(digest, .lower)})
    else
        try gpa.print("printf '%s' {s} >/data/postdoc-check.js; " ++
            "wget -q -T 300 -O - --header \"Authorization: Bearer $t\" " ++
            "--header 'X-Filename: add.js' --post-file /data/postdoc-check.js " ++
            "'http://127.0.0.1:49999/v1/analyze?force=1'", .{try host.check.quote(gpa, sample)});
    return gpa.print(
        "t=$(cat /run/config/postdoc/api-token); {s} | grep -q '\"decision\":\"allow\"'{s}",
        .{ request, if (resumed) "" else " && sync" },
    );
}
