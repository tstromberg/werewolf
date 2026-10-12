//! neo4j-boot starts Neo4j. JNA's library is already on the root, one
//! directory per arch: a temporary directory is noexec, so Neo4j cannot
//! unpack it there. JAVA_TOOL_OPTIONS reaches the server Neo4j starts as
//! a child, which does not keep this process's own flags. Its seed file
//! is /dev/urandom; the floor allows /dev/random as well.
//!
//!     neo4j-boot
//!
//! leash runs it as the neo4j user (forms/bloodhound/form.yaml).

const std = @import("std");
const builtin = @import("builtin");

const jna = switch (builtin.cpu.arch) {
    .aarch64 => "/usr/lib/jna/aarch64",
    .x86_64 => "/usr/lib/jna/x86_64",
    else => @compileError("no JNA library for this arch"),
};
const tool_options = "-Djna.nosys=true -Djna.boot.library.path=" ++ jna ++
    " -Djava.security.egd=file:/dev/urandom";

pub fn main(init: std.process.Init) void {
    const io = init.io;
    init.environ_map.put("JAVA_TOOL_OPTIONS", tool_options) catch std.process.exit(1);
    std.process.replace(io, .{
        .argv = &.{
            "/usr/bin/java",
            "-Xms256m",
            "-Xmx1g",
            "-XX:+UseG1GC",
            "-Djava.io.tmpdir=/run/svc/neo4j",
            "-Djava.security.egd=file:/dev/urandom",
            "-Djna.nosys=true",
            "-Djna.boot.library.path=" ++ jna,
            "-Dfile.encoding=UTF-8",
            "-Dapp.name=neo4j",
            "-Dapp.home=/var/lib/neo4j",
            "-Dbasedir=/var/lib/neo4j",
            "-classpath",
            "/var/lib/neo4j/lib/*",
            "org.neo4j.server.startup.Neo4jBoot",
            "console",
        },
        .environ_map = init.environ_map,
    }) catch std.process.exit(1);
}
