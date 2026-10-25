//! host is what host-side tests share: build it as module host with
//! -Mhost=test/host/host.zig. See README.md.

pub const tls = @import("tls.zig");
pub const http = @import("http.zig");
pub const qmp = @import("qmp.zig");
pub const qemu = @import("qemu.zig");
pub const check = @import("check.zig");
pub const Check = check.Check;
pub const swtpm = @import("swtpm.zig");
pub const evidence = @import("evidence.zig");
pub const provider = @import("provider.zig");
pub const pem = @import("pem.zig");
pub const consumer = @import("consumer.zig");
pub const netns = @import("netns.zig");
pub const dnswire = @import("dnswire.zig");
pub const sqlite = @import("sqlite.zig");

test {
    _ = tls;
    _ = http;
    _ = qmp;
    _ = qemu;
    _ = check;
    _ = swtpm;
    _ = evidence;
    _ = provider;
    _ = pem;
    _ = consumer;
    _ = netns;
    _ = dnswire;
    _ = sqlite;
}
