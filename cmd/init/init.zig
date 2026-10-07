//! init: PID 1 from stage0 handing over until runit takes it.
//!
//! stage0 has mounted the form's root.erofs read-only at / and handed over:
//! nothing here or after can write the root, so what changes lives in /run,
//! /tmp, /var/tmp and /data. init only has to make the machine reachable:
//! filesystems, the kernel's settings, one address, the operator's keys,
//! /data. Then it hands over to fence, which sets the network policy and
//! becomes runit; /etc/runit/2 runs the services and /etc/runit/3 shuts down.
//!
//! Every form includes minimal, so this program is in every image. It must
//! not know which form it is in: it prepares the machine and starts runit,
//! and the services a form adds take care of themselves. It decides from
//! what the image carries (a DHCP client, mke2fs, cryptsetup) and what it
//! is told, instead.
//!
//! Everything it reads comes from two places, in this order:
//!
//!     kernel command line   werewolf.ip=CIDR werewolf.gw=ADDR werewolf.dns=ADDR
//!                             (without werewolf.ip, the address is DHCP's)
//!                           werewolf.mac=ADDR (which NIC, when there are several)
//!                           werewolf.data=DEV (/data on a disk: DEV, formatted once)
//!                           (werewolf.debug=1, a root shell on the console where
//!                             the form has one, is the debug-shell service's)
//!                           and, on a machine with slots:
//!                           werewolf.victim=UUID:DIR (the filesystem holding the
//!                             slots, config.tar and data/)
//!                           werewolf.grubenv=UUID:PATH (GRUB's environment block,
//!                             which the slot-keep service writes)
//!     config                one tar: config.tar in the victim's directory, or
//!                           else the first block device written with one;
//!                           never two, merged. It is extracted to /run/config,
//!                           by a confined child, for the services to read
//!                           (hostname and authorized_keys are applied here).
//!                           Beside it, a NoCloud volume labelled `cidata`, from
//!                           which the first user, its ssh keys and Lima's data
//!                           files beneath /run/config are taken, never in
//!                           place of the tar's, and without running
//!                           provisioning scripts. Failing both, the cloud's
//!                           metadata server.
//!
//! It runs no shell. What it cannot do itself it asks of werewolf's programs
//! (mount, modules, net, dhcp, cloud, fence) and of the filesystem tools the
//! form carries (blkid, mke2fs, e2fsck, cryptsetup), each by its full path.
//! A step that fails is said on the console and the boot goes on, as far as
//! it can; only failing to start fence ends it, which panics the kernel and
//! sends the machine back to its last good slot.

const std = @import("std");
const builtin = @import("builtin");
const seal_lib = @import("seal");
const sandbox = @import("sandbox");
const network_file = @import("network");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const mount_bin = "/usr/lib/werewolf/mount";
const path_env = "/usr/sbin:/usr/bin:/sbin:/bin";
const label = "werewolf-data";
const max_config_file = 1 << 20;
/// What a config tar may hold in all, so one from a disk cannot fill /run.
const max_config_total = 16 << 20;
const max_config_entries = 256;
/// The least data.key LUKS is made with: the key derivation is quick, as a
/// random key needs no slow one, so the key itself must be strong.
const min_data_key = 32;

pub fn main(init: std.process.Init) !void {
    var m: Machine = .{
        .io = init.io,
        .gpa = init.arena.allocator(),
        .env = try init.environ_map.clone(init.arena.allocator()),
    };
    try m.env.put("PATH", path_env);
    // Where the boot's time goes: stage0's phases, then init's, each marked
    // as it ends. Taken out of the environment before anything is started;
    // the names point into a copy, since removing the variable frees it.
    var phases = Phases.parse(try m.gpa.dupe(u8, m.env.get("WEREWOLF_BOOT") orelse ""));
    _ = m.env.swapRemove("WEREWOLF_BOOT");

    // Nothing here may wait on a person. A tool that prompts (mke2fs does,
    // over an old signature) reads end of file instead of stalling the boot.
    const null_fd = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(null_fd) == .SUCCESS) _ = linux.dup2(@intCast(null_fd), 0);

    m.filesystems();
    m.seed();
    m.cmd = parseCmdline(m.read("/proc/cmdline"));
    phases.add("mounts", bootMs());
    m.kernel() catch {
        say("the kernel's protections are not all set; not handing over", .{});
        std.process.exit(1);
    };
    phases.add("sysctls", bootMs());
    // The config on the machine's disks first, since it may hold the
    // network; the cloud's, which comes over the network, after it.
    m.victim();
    phases.add("victim", bootMs());
    m.config();
    phases.add("config", bootMs());
    m.network();
    phases.add("network", bootMs());
    m.metadata();
    phases.add("metadata", bootMs());
    m.data();
    phases.add("data", bootMs());

    if (m.cmd.grubenv.len > 0) m.write(
        "/run/werewolf/grubenv",
        m.fmt("{s}\n", .{m.cmd.grubenv}),
        0o644,
    );

    // fence sets the network policy the build compiled from the forms,
    // binding only declared TCP ports and the metadata server only for those
    // named, then becomes runit, so every process inherits it. If it cannot,
    // PID 1 ends, and the machine falls back to the slot that last worked.
    // No core dumps, by anyone it starts: a crash leaves no copy of a
    // program's memory, and its secrets, behind. A hard limit, so no
    // process can raise its own.
    const no_core: linux.rlimit = .{ .cur = 0, .max = 0 };
    if (linux.errno(linux.setrlimit(
        .CORE,
        &no_core,
    )) != .SUCCESS) say("core dumps not limited", .{});
    // The seal fails closed, as fence does: PID 1 ends, the kernel panics,
    // and the machine comes back on the slot that last worked.
    seal(&m) catch |err| {
        say("not sealed: {s}; not handing over", .{@errorName(err)});
        std.process.exit(1);
    };
    // The mount broker (cmd/mount-broker), which mounts for the few that
    // must once fence's Landlock domain forbids mounting to everyone in
    // it: started here, so it is outside that domain, and after the seal,
    // so it is under it like every other process. It never exits; without
    // it nothing can keep this slot, so a machine whose broker would not
    // start falls back to the slot that last worked.
    if (std.process.spawn(m.io, .{
        .argv = &.{"/usr/lib/werewolf/mount-broker"},
        .environ_map = &m.env,
        .stdin = .ignore,
    })) |_| {} else |broker_err| say("no mount broker: {s}", .{@errorName(broker_err)});
    // The DHCP lease's renewal (cmd/dhcp-client), started here too, so it
    // keeps CAP_NET_ADMIN to apply a lease, and its packet socket, which
    // fence then takes from every process after it, root's included: no
    // form need keep either for DHCP. runit does not restart it; should it
    // end, the address it applied stays.
    if (m.dhcp) if (std.process.spawn(m.io, .{
        .argv = &.{ "/usr/lib/werewolf/dhcp-client", "keep" },
        .environ_map = &m.env,
        .stdin = .ignore,
    })) |_| {} else |dhcp_err| say("no DHCP renewal: {s}", .{@errorName(dhcp_err)});
    // The seal, and starting the broker and the renewal.
    phases.add("seal", bootMs());
    // How long the boot took, for the console and the demo's page: the
    // kernel's part, which stage0 measured, and userland's, stage0 and init,
    // phase by phase.
    const kernel_ms = phases.endOf("kernel");
    const up_ms = bootMs();
    const took = phases.durations(m.gpa);
    m.write(
        "/run/werewolf/boot",
        m.fmt("{s}\n", .{std.json.Stringify.valueAlloc(m.gpa, .{
            .kernel_ms = kernel_ms,
            .userland_ms = up_ms -| kernel_ms,
            .phases = took,
        }, .{}) catch ""}),
        0o644,
    );
    var line: Io.Writer.Allocating = .init(m.gpa);
    for (took, 0..) |p, i| line.writer.print("{s}{s} {d}.{d:0>3}s", .{
        if (i == 0) "" else ", ", p.name, p.ms / 1000, p.ms % 1000,
    }) catch {};
    say("phases: {s}", .{line.written()});
    say("up in {s}s (the kernel {s}s, userland {s}s), handing over to runit", .{
        m.fmt("{d}.{d:0>3}", .{ up_ms / 1000, up_ms % 1000 }),
        m.fmt("{d}.{d:0>3}", .{ kernel_ms / 1000, kernel_ms % 1000 }),
        m.fmt("{d}.{d:0>3}", .{ (up_ms -| kernel_ms) / 1000, (up_ms -| kernel_ms) % 1000 }),
    });
    const err = std.process.replace(
        m.io,
        .{ .argv = &.{ "/usr/lib/werewolf/fence", "/usr/bin/runit" }, .environ_map = &m.env },
    );
    say("cannot start fence: {s}", .{@errorName(err)});
    std.process.exit(1);
}

const Machine = struct {
    io: Io,
    gpa: Allocator,
    env: std.process.Environ.Map,
    cmd: Cmdline = .{},
    victim_dir: []const u8 = "",
    nocloud_user: []const u8 = "",
    /// Whether a config tar or a NoCloud seed was found on a disk, so the
    /// cloud's metadata server is not asked.
    configured: bool = false,
    /// Whether the address is DHCP's, for its renewal to be started.
    dhcp: bool = false,

    // --- filesystems ---------------------------------------------------------

    /// Every mount is werewolf's own (cmd/mount/mount.zig): nosuid and noexec
    /// unless told otherwise, nodev but on device filesystems, and unable to
    /// lift a restriction a mount already has. stage0 mounted the first three
    /// and moved them here, so they are remounted with the same options
    /// either way. Nothing written to memory may run or be setuid: the RAM
    /// filesystems are noexec, and only /tmp, /var/tmp and /dev/shm are
    /// writable by everyone. /proc shows each user only their own processes.
    fn filesystems(m: *Machine) void {
        if (!m.isMounted("/proc")) m.mount(&.{ "-t", "proc", "proc", "/proc" });
        if (!m.isMounted("/sys")) m.mount(&.{ "-t", "sysfs", "sys", "/sys" });
        if (!m.isMounted("/dev")) m.mount(&.{ "-t", "devtmpfs", "dev", "/dev" });
        m.mount(&.{ "-o", "remount,nosuid,nodev,noexec,hidepid=invisible", "/proc" });
        m.mount(&.{ "-o", "remount,nosuid,nodev,noexec", "/sys" });
        m.mount(&.{ "-o", "remount,nosuid,noexec", "/dev" });
        for ([_][:0]const u8{ "/dev/pts", "/dev/shm" }) |d| mkdir(d, 0o755);
        // Pseudo-terminals only where the form allows them (pty): ssh
        // logins. Without devpts mounted, /dev/ptmx opens nothing (ENODEV),
        // so the TTY layer's pseudo-terminal code (CVE-2014-0196) is out of
        // reach of every process, root included, and nothing after boot
        // can mount it.
        if (exists("/etc/werewolf/allow/pty"))
            m.mount(&.{ "-t", "devpts", "-o", "nosuid,noexec", "devpts", "/dev/pts" })
        else
            say("no pseudo-terminals: the form does not allow pty", .{});
        m.mount(&.{ "-t", "tmpfs", "-o", "nosuid,nodev,noexec,mode=1777", "tmpfs", "/dev/shm" });
        m.mount(&.{ "-t", "tmpfs", "-o", "nosuid,nodev,noexec,mode=0755", "tmpfs", "/run" });
        m.mount(&.{ "-t", "tmpfs", "-o", "nosuid,nodev,noexec,mode=1777", "tmpfs", "/tmp" });
        m.mount(&.{
            "-t",
            "tmpfs",
            "-o",
            "nosuid,nodev,noexec,mode=1777,size=25%",
            "tmpfs",
            "/var/tmp",
        });
        mkdir("/run/config", 0o700);
        m.cgroups();
    }

    /// A cgroup2 hierarchy for the leashed services (cmd/leash), under /run
    /// rather than /sys so fence's domain -- which keeps /sys read-only --
    /// still lets leash and the finish reaper manage it through the /run it
    /// may write. memory and pids are delegated to the svc subtree, so a
    /// service gets a memory ceiling and its whole process tree, detached
    /// children included, is killed when it stops (its finish writes
    /// cgroup.kill). Without cgroup2 or its controllers, services still run,
    /// uncapped and without that reaper.
    fn cgroups(m: *Machine) void {
        mkdir("/run/cgroup", 0o755);
        if (!m.run(&.{
            mount_bin,
            "-t",
            "cgroup2",
            "-o",
            "nosuid,nodev,noexec",
            "cgroup2",
            "/run/cgroup",
        })) return say("no cgroup2; services run uncapped and unreaped", .{});
        if (!writeFile("/run/cgroup/cgroup.subtree_control", "+memory +pids"))
            return say("cgroup2 without memory/pids; services run uncapped", .{});
        mkdir("/run/cgroup/svc", 0o755);
        _ = writeFile("/run/cgroup/svc/cgroup.subtree_control", "+memory +pids");
        say("cgroups: a memory cap and a reaper per service", .{});
    }

    /// What init and the services change of the read-only root lives in
    /// /run, where the image's /etc links: the accounts, seeded from the
    /// image's own copies, the hostname, the resolvers, root's and users' ssh
    /// keys, runit's controls and each service's supervise directory.
    fn seed(m: *Machine) void {
        for ([_][:0]const u8{
            "/run/werewolf",
            "/run/werewolf/keys",
            "/run/runit",
        }) |d| mkdir(d, 0o755);
        for ([_][]const u8{ "passwd", "group", "shadow" }) |f| {
            const src = m.fmt("/usr/share/werewolf/etc/{s}", .{f});
            const text = m.read(src);
            if (text.len == 0) {
                say("cannot read {s}", .{src});
                continue;
            }
            m.write(
                m.fmt("/run/werewolf/{s}", .{f}),
                text,
                if (std.mem.eql(u8, f, "shadow")) 0o600 else 0o644,
            );
        }
        for (m.list("/etc/sv")) |s| mkdir(m.fmtZ("/run/runit/supervise.{s}", .{s}), 0o755);
    }

    // --- the kernel ----------------------------------------------------------

    /// Lockdown first. At integrity the kernel loads only modules signed by
    /// the key it was built with (Alpine's), so a module that is not is
    /// refused, not merely logged; it only ever rises, so init raises it
    /// here rather than trusting whatever command line the machine booted
    /// with. stage0 has raised it already. Then the modules, and the loader
    /// closes for the life of the machine (cmd/modload/modload.zig); stage0 has
    /// done both, and the loader says so. Then the settings.
    fn kernel(m: *Machine) !void {
        if (!m.isMounted("/sys/kernel/security")) m.mount(&.{
            "-t",
            "securityfs",
            "securityfs",
            "/sys/kernel/security",
        });
        m.mount(&.{ "-o", "remount,nosuid,nodev,noexec", "/sys/kernel/security" });
        const lockdown = "/sys/kernel/security/lockdown";
        if (std.mem.indexOf(
            u8,
            m.read(lockdown),
            "[none]",
        ) != null) _ = writeFile(lockdown, "integrity");
        say("lockdown: {s}", .{lockdownLevel(m.read(lockdown))});

        if (!m.run(&.{"/usr/lib/werewolf/modload"})) say("not every module loaded; see above", .{});

        var all = true;
        // Each is a protection, so one the kernel refuses ends the boot, and
        // the machine returns on the slot that last worked, as the seal and
        // fence do. werewolf's kernel has every one. A container's /proc/sys
        // is read-only (EROFS), and these are the host's to set: that case,
        // and that one alone, is said and passed.
        for (sysctls) |kv| switch (writeErrno(m.fmtZ("/proc/sys/{s}", .{kv[0]}), kv[1])) {
            .SUCCESS => {},
            .ROFS => all = false,
            else => |e| {
                say("sysctl {s} not set: {t}", .{ kv[0], e });
                return error.Sysctl;
            },
        };
        // Redirects, per interface: a host takes or sends them on one if all
        // or the interface says so, and all and default do not reach the
        // interfaces stage0's drivers made before now. IPv6 has only the
        // interface's own setting.
        for (m.list("/proc/sys/net/ipv4/conf")) |c| for ([_][]const u8{
            "accept_redirects",
            "secure_redirects",
            "send_redirects",
        }) |k| {
            if (!writeFile(m.fmtZ("/proc/sys/net/ipv4/conf/{s}/{s}", .{ c, k }), "0")) all = false;
        };
        for (m.list("/proc/sys/net/ipv6/conf")) |c| {
            if (!writeFile(
                m.fmtZ("/proc/sys/net/ipv6/conf/{s}/accept_redirects", .{c}),
                "0",
            )) all = false;
        }
        if (!all) say("some sysctls were not applied", .{});
        // A panic reboots in the seconds the command line gave (bite's and
        // boot/mkdisk's say 10), or, given none, in 10: the kernel's own
        // default is to hang, and an oops now panics.
        if (std.mem.eql(u8, trim(m.read("/proc/sys/kernel/panic")), "0") and
            !writeFile(
                "/proc/sys/kernel/panic",
                "10",
            )) say("kernel.panic not set; a panic will hang", .{});
    }

    // --- the network ---------------------------------------------------------

    /// One address: the command line's, or else the config tar's network
    /// file's, or else, in forms built on dhcp, the network's DHCP server's.
    /// A static address is for machines whose provider gives none by DHCP,
    /// or which bite took over and so keep the victim's; werewolf's net
    /// (cmd/iface-up/iface-up.zig) applies it. DHCP is werewolf's
    /// own client (cmd/dhcp-client/dhcp-client.zig), which applies the lease, logs it, and
    /// keeps the resolvers in its own directory; its renewal starts before fence.
    fn network(m: *Machine) void {
        _ = m.run(&.{ "/usr/lib/werewolf/iface-up", "lo" });
        const nic = m.pickNic();
        m.routerAdvertisements(nic);
        var from: []const u8 = "";
        const c = m.staticNetwork(&from);
        if (nic.len == 0) {
            if (m.cmd.mac.len > 0)
                say("no network: no NIC with address {s}", .{m.cmd.mac})
            else
                say("no network: no NIC", .{});
        } else if (c.ip.len > 0) {
            const ok = if (c.gw.len > 0)
                m.run(&.{ "/usr/lib/werewolf/iface-up", nic, c.ip, c.gw })
            else
                m.run(&.{ "/usr/lib/werewolf/iface-up", nic, c.ip });
            if (!ok) {
                if (c.gw.len > 0)
                    say("network: {s} {s} via {s} refused", .{ nic, c.ip, c.gw })
                else
                    say("network: {s} {s} refused", .{ nic, c.ip });
            }
            if (c.dns.len > 0) m.write(
                "/run/resolv.conf",
                m.fmt("nameserver {s}\n", .{c.dns}),
                0o644,
            );
            say(
                "{s} {s} via {s} dns {s}, from {s}",
                .{ nic, c.ip, orNone(c.gw), orNone(c.dns), from },
            );
        } else if (executable("/usr/lib/werewolf/dhcp-client")) {
            m.dhcp = true;
            _ = linux.unlink("/run/resolv.conf");
            _ = linux.symlink("werewolf/dhcp/resolv.conf", "/run/resolv.conf");
            if (!m.run(&.{
                "/usr/lib/werewolf/dhcp-client",
                "up",
                nic,
            })) say("no network: no DHCP lease for {s}; its renewal keeps asking", .{nic});
        } else {
            say(
                "no network: no werewolf.ip, no network file in the config tar, and this form " ++
                    "has no DHCP client",
                .{},
            );
        }
    }

    /// The static address, and where it came from: the command line's
    /// werewolf.ip, or else the config tar's network file, checked as
    /// werewolf pack checks it (lib/network.zig). The command line wins,
    /// since whoever set it holds the boot; a file refused is said and
    /// left, as if absent.
    fn staticNetwork(m: *Machine, from: *[]const u8) network_file.Network {
        const has_file = exists("/run/config/network");
        if (m.cmd.ip.len > 0) {
            if (has_file) say(
                "network: the command line's, not the config tar's network file",
                .{},
            );
            from.* = "the command line";
            return .{ .ip = m.cmd.ip, .gw = m.cmd.gw, .dns = m.cmd.dns };
        }
        if (!has_file) return .{};
        var why: []const u8 = "";
        const n = network_file.parse(m.read("/run/config/network"), &why) orelse {
            say("network: the config tar's network file refused: {s}", .{why});
            return .{};
        };
        from.* = "the config tar";
        return n;
    }

    /// The NIC: the one werewolf.mac names, or else the first but lo.
    /// IPv6 is on, and router advertisements are how most networks give it a
    /// route, so they are taken, but on the machine's NIC alone, before it
    /// is up, and only for what they must give: a rogue router on the same
    /// network cannot rank itself above the real one, add a more specific
    /// route to steal one destination's traffic, or flood the NIC with
    /// addresses. Interfaces made later (default) take none.
    fn routerAdvertisements(m: *Machine, nic: []const u8) void {
        var all = true;
        for (m.list("/proc/sys/net/ipv6/conf")) |c| {
            const d = m.fmt("/proc/sys/net/ipv6/conf/{s}", .{c});
            for ([_][2][]const u8{
                .{ "accept_ra_rtr_pref", "0" },
                .{ "accept_ra_rt_info_max_plen", "0" },
                .{ "max_addresses", "4" },
            }) |kv| {
                if (!writeFile(m.fmtZ("{s}/{s}", .{ d, kv[0] }), kv[1])) all = false;
            }
            // all's accept_ra governs no interface; each has its own.
            if (!std.mem.eql(u8, c, nic) and !std.mem.eql(u8, c, "all") and
                !writeFile(m.fmtZ("{s}/accept_ra", .{d}), "0")) all = false;
        }
        if (!all) say("some IPv6 router advertisement limits were not applied", .{});
    }

    fn pickNic(m: *Machine) []const u8 {
        for (m.list("/sys/class/net")) |n| {
            if (std.mem.eql(u8, n, "lo")) continue;
            if (m.cmd.mac.len == 0) return n;
            const addr = trim(m.read(m.fmt("/sys/class/net/{s}/address", .{n})));
            if (std.ascii.eqlIgnoreCase(addr, m.cmd.mac)) return n;
        }
        return "";
    }

    // --- the victim ----------------------------------------------------------

    /// On a machine with slots, the filesystem holding them also holds, in
    /// one directory, config.tar and data/ for /data. stage0 has mounted it
    /// already, to read root.erofs.
    fn victim(m: *Machine) void {
        const v = m.cmd.victim;
        if (v.len == 0) return;
        const colon = std.mem.findScalar(
            u8,
            v,
            ':',
        ) orelse return say("victim's filesystem {s} not found", .{v});
        // stage0 mounts it before it hands over, or the machine never gets
        // here (werewolf.victim comes only with werewolf.slot). Its device
        // is the kernel's word, from the mount table, not a second search
        // of every disk that could name a different one.
        const dev = m.mountSource("/victim") orelse
            return say("victim's filesystem {s} is not on /victim", .{v[0..colon]});
        m.victim_dir = m.fmt("/victim{s}", .{v[colon + 1 ..]});
        say("victim's filesystem {s} on /victim, werewolf in {s}", .{ dev, m.victim_dir });
    }

    // --- the config ----------------------------------------------------------

    /// One config tar: the victim's config.tar, or else the first block
    /// device holding one ("ustar" at byte 257). Never a merge: any other is
    /// said and ignored, so a disk someone attached cannot quietly replace
    /// root's keys. Then a NoCloud seed, but only an ISO9660 volume labelled
    /// cidata, found in the same pass by its volume descriptor alone, so no
    /// other disk is ever mounted to look, and no blkid probes every
    /// superblock of every disk (85 ms on GCP's network disks, where there
    /// is never a seed); the first, and any other said and ignored, as a
    /// second tar is. Before the network, as the tar may hold its address.
    fn config(m: *Machine) void {
        var tar: ?[]const u8 = null;
        if (m.victim_dir.len > 0) {
            const t = m.fmt("{s}/config.tar", .{m.victim_dir});
            if (exists(m.z(t))) {
                say("config tar in {s}", .{m.victim_dir});
                tar = t;
            }
        }
        var seed_dev: ?[:0]const u8 = null;
        for (m.list("/sys/class/block")) |name| {
            const dev = m.fmtZ("/dev/{s}", .{name});
            if (!isBlockDevice(dev)) continue;
            if (isNoCloud(dev)) {
                if (seed_dev) |s|
                    say("NoCloud seed on {s} ignored: the seed is {s}", .{ dev, s })
                else
                    seed_dev = dev;
                continue;
            }
            if (!hasUstar(dev)) continue;
            if (tar) |t| {
                say("config tar on {s} ignored: the config is {s}", .{ dev, t });
                continue;
            }
            say("config tar on {s}", .{dev});
            tar = dev;
        }
        if (tar) |t| m.extract(t);

        var seeded = false;
        if (seed_dev) |cidata| {
            if (m.runQuiet(&.{ mount_bin, "-t", "iso9660", "-o", "ro", cidata, "/mnt" })) {
                if (exists("/mnt/user-data")) {
                    say("NoCloud user-data on {s}", .{cidata});
                    seeded = true;
                    m.nocloud();
                }
                _ = linux.umount2("/mnt", 0);
            }
        }
        m.configured = tar != null or seeded;
    }

    /// Where no disk held a config and the form has werewolf's cloud
    /// program, the config from the cloud's metadata server, checked and
    /// rewritten by that program first (docs/cloud.md); a network file in
    /// it comes too late, the network being up to fetch it. Then the
    /// hostname and root's keys, from whichever config there is.
    fn metadata(m: *Machine) void {
        if (!m.configured and executable("/usr/lib/werewolf/cloud-metadata") and
            m.run(&.{"/usr/lib/werewolf/cloud-metadata"}) and
            exists("/run/werewolf/cloud/config.tar"))
        {
            say("config tar from the cloud's metadata server", .{});
            m.extract("/run/werewolf/cloud/config.tar");
            if (exists("/run/config/network"))
                say(
                    "network: the cloud's network file is not read: the network was up to fetch it",
                    .{},
                );
        }

        const name = if (exists("/run/config/hostname"))
            trim(firstLine(m.read("/run/config/hostname")))
        else
            "werewolf";
        const host = if (isHostname(name)) name else blk: {
            say("hostname '{s}' refused: not a plain name", .{name});
            break :blk "werewolf";
        };
        m.write("/run/werewolf/hostname", m.fmt("{s}\n", .{host}), 0o644);
        // The machine's own name resolves, to itself, with no DNS: programs
        // that look it up (Java's getLocalHost) need it, and a lookup that
        // left the machine would say its name to the network.
        m.write("/run/werewolf/hosts", m.fmt(
            "127.0.0.1\tlocalhost {s}\n::1\t\tlocalhost {s}\n",
            .{ host, host },
        ), 0o644);
        _ = linux.syscall2(.sethostname, @intFromPtr(host.ptr), host.len);
        if (exists("/run/config/authorized_keys")) m.keys(
            "root",
            m.read("/run/config/authorized_keys"),
        );
    }

    /// The first user in a NoCloud cloud-config and every ssh key in it,
    /// which is what Lima provides. The name and uid come from outside the
    /// machine: plain ones only. Written directly, since /etc is read-only:
    /// "*" is no password, without the lock "!" that sshd reads as refusing
    /// even a key. Home is on /data.
    fn nocloud(m: *Machine) void {
        m.limaConfig();
        const nc = parseNoCloud(m.gpa, m.read("/mnt/user-data")) catch return;
        if (nc.user.len > 0) {
            const passwd = m.read("/run/werewolf/passwd");
            if (isPlainUser(nc.user) and isPlainUid(nc.uid) and !hasEntry(passwd, nc.user) and
                !idInUse(passwd, nc.uid) and !idInUse(m.read("/run/werewolf/group"), nc.uid))
            {
                m.append(
                    "/run/werewolf/passwd",
                    m.fmt(
                        "{s}:x:{s}:{s}::/data/home/{s}:/bin/ash\n",
                        .{ nc.user, nc.uid, nc.uid, nc.user },
                    ),
                );
                m.append("/run/werewolf/group", m.fmt("{s}:x:{s}:\n", .{ nc.user, nc.uid }));
                m.append("/run/werewolf/shadow", m.fmt("{s}:*:0:0:99999:7:::\n", .{nc.user}));
                m.keys(nc.user, nc.keys);
                m.nocloud_user = nc.user;
            } else {
                say(
                    "NoCloud user '{s}' (uid {s}) refused: not a plain name, or a uid from 500 " ++
                        "to 60000 no account has",
                    .{ nc.user, nc.uid },
                );
            }
        }
        // Lima's readiness probe reads the instance-id back from here; it is
        // what cloud-init's boot scripts would have written.
        const id = instanceId(m.read("/mnt/meta-data"));
        m.write("/run/lima-boot-done", if (id.len > 0) m.fmt("{s}\n", .{id}) else "", 0o644);
    }

    /// Import only Lima's data provisioning into root-private /run/config.
    /// Treat lima.env as data, never source it or run any cidata script.
    fn limaConfig(m: *Machine) void {
        var cidata = Dir.cwd().openDir(m.io, "/mnt", .{ .follow_symlinks = false }) catch return;
        defer cidata.close(m.io);
        const env = readLimaFile(m.gpa, m.io, cidata, "lima.env") catch |err| switch (err) {
            error.FileNotFound => return,
            else => return say("Lima config refused: {s}", .{@errorName(err)}),
        };
        const files = limaDataFiles(m.gpa, env) catch |err|
            return say("Lima config refused: {s}", .{@errorName(err)});
        if (files.len == 0) return;
        // Read and check every source before writing any destination.
        const values = readLimaData(m.gpa, m.io, cidata, files) catch |err|
            return say("Lima config refused: {s}", .{@errorName(err)});
        var n: usize = 0;
        for (files, values) |file, value| {
            const dest = m.fmt("/run/config/{s}", .{file.name});
            // The config tar's word stands: Lima's adds, never replaces.
            if (exists(m.z(dest))) {
                say("Lima config: {s} kept, as the config tar gave it", .{file.name});
                continue;
            }
            if (std.fs.path.dirname(dest)) |parent| m.mkdirAll(m.z(parent));
            m.write(dest, value, 0o600);
            n += 1;
        }
        say("Lima config: imported {d} data files", .{n});
    }

    /// user's ssh keys, where sshd looks (AuthorizedKeysFile).
    fn keys(m: *Machine, user: []const u8, text: []const u8) void {
        const path = m.fmtZ("/run/werewolf/keys/{s}", .{user});
        m.write(path, text, 0o600);
        const ids = lookupIds(m.read("/run/werewolf/passwd"), user) orelse return;
        _ = linux.fchownat(linux.AT.FDCWD, path, ids.uid, ids.gid, 0);
    }

    /// A config tar into /run/config, by a child that can do nothing else:
    /// root's uid with no capabilities, Landlock letting it write beneath
    /// /run/config alone and read nothing else, and a filter of file calls
    /// alone. It reads the whole tar once to check its size, then extracts
    /// it, or nothing: at most 256 entries and 16 MiB. Regular files and
    /// directories only, each name relative and plain, no file over 1 MiB;
    /// files 0600 and directories 0700, root's.
    fn extract(m: *Machine, path: []const u8) void {
        const src = linux.open(m.z(path), .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
        if (linux.errno(src) != .SUCCESS)
            return say("config: {s}: {t}", .{ path, linux.errno(src) });
        defer _ = linux.close(@intCast(src));
        const dir = linux.open(
            "/run/config",
            .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true },
            0,
        );
        if (linux.errno(dir) != .SUCCESS)
            return say("config: /run/config: {t}", .{linux.errno(dir)});
        defer _ = linux.close(@intCast(dir));
        const pid = linux.fork();
        if (linux.errno(pid) != .SUCCESS) return say("config: fork: {t}", .{linux.errno(pid)});
        if (pid == 0) m.extractChild(@intCast(src), @intCast(dir), path);
        var status: i32 = 0;
        while (linux.errno(linux.wait4(@intCast(pid), &status, 0, null)) == .INTR) {}
        const st: u32 = @bitCast(status);
        if (!linux.W.IFEXITED(st) or linux.W.EXITSTATUS(st) != 0)
            say("config: {s} not extracted", .{path});
    }

    /// The child of extract: confined, then the tar checked whole, then
    /// written.
    fn extractChild(m: *Machine, src: i32, dir: i32, path: []const u8) noreturn {
        confineExtract(dir) catch {
            say("config: cannot confine the extraction: {s} {s}", .{
                sandbox.failed, sandbox.errnoName(sandbox.failed_errno),
            });
            linux.exit_group(1);
        };
        const f: Io.File = .{ .handle = src, .flags = .{ .nonblocking = false } };
        const out: Dir = .{ .handle = dir };
        sizeUp(m, f) catch |err| {
            say("config: {s} refused: {s}", .{ path, @errorName(err) });
            linux.exit_group(1);
        };
        if (linux.errno(linux.lseek(src, 0, linux.SEEK.SET)) != .SUCCESS) linux.exit_group(1);
        writeOut(m, f, out) catch |err| {
            say("config: {s}: {s}", .{ path, @errorName(err) });
            linux.exit_group(1);
        };
        linux.exit_group(0);
    }

    /// The tar's entries and file bytes counted, before anything is written.
    fn sizeUp(m: *Machine, f: Io.File) !void {
        var rbuf: [8192]u8 = undefined;
        var r = f.readerStreaming(m.io, &rbuf);
        var name_buf: [Dir.max_path_bytes]u8 = undefined;
        var link_buf: [Dir.max_path_bytes]u8 = undefined;
        var it: std.tar.Iterator = .init(
            &r.interface,
            .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
        );
        var entries: usize = 0;
        var total: u64 = 0;
        while (try it.next()) |e| {
            entries += 1;
            if (e.kind == .file) total += e.size;
            if (entries > max_config_entries) return error.TooManyEntries;
            if (total > max_config_total) return error.TooLarge;
        }
    }

    /// Each entry written beneath out: what is not plain is said and left.
    fn writeOut(m: *Machine, f: Io.File, out: Dir) !void {
        var rbuf: [8192]u8 = undefined;
        var r = f.readerStreaming(m.io, &rbuf);
        var name_buf: [Dir.max_path_bytes]u8 = undefined;
        var link_buf: [Dir.max_path_bytes]u8 = undefined;
        var it: std.tar.Iterator = .init(
            &r.interface,
            .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
        );
        while (try it.next()) |e| {
            const name = safeName(e.name) orelse {
                say("config: {s} refused: not a plain relative name", .{e.name});
                continue;
            };
            if (name.len == 0) continue;
            switch (e.kind) {
                .directory => out.createDirPath(m.io, name) catch |err|
                    say("config: {s}: {s}", .{ name, @errorName(err) }),
                .sym_link => say("config: {s} refused: a link", .{name}),
                .file => {
                    if (e.size > max_config_file) {
                        say("config: {s} refused: over 1 MiB", .{name});
                        continue;
                    }
                    if (std.fs.path.dirname(name)) |parent| out.createDirPath(
                        m.io,
                        parent,
                    ) catch {};
                    var file = out.createFile(
                        m.io,
                        name,
                        .{ .permissions = .fromMode(0o600) },
                    ) catch |err| {
                        say("config: {s}: {s}", .{ name, @errorName(err) });
                        continue;
                    };
                    defer file.close(m.io);
                    var wbuf: [8192]u8 = undefined;
                    var w = file.writer(m.io, &wbuf);
                    try it.streamRemaining(e, &w.interface);
                    try w.interface.flush();
                },
            }
        }
    }

    // --- /data ---------------------------------------------------------------

    /// /data is the machine's one writable home, and what is on it may be
    /// the only copy: a database, someone's files. So init formats a disk
    /// once, when werewolf.data names it and blkid finds nothing on it at
    /// all, and never again. A disk that carries our label but is not what
    /// the form wants (plain where it wants LUKS, no key or a key that does
    /// not open it, damage that e2fsck -p will not repair) is left as it is,
    /// for a person to look at.
    ///
    /// /data is then unavailable: an empty, read-only tmpfs, so a service
    /// that needs it fails where it can be seen, rather than writing to RAM
    /// what it believes is kept. /run/werewolf/nodata says why, and stops a
    /// slot on probation from committing, so an update that broke /data
    /// falls back.
    ///
    /// The command line and the config decide what /data is, never which
    /// form this is; the form only has the tools or not:
    ///
    ///     no werewolf.data, or no mke2fs   tmpfs, capped at a quarter of RAM: nothing is kept
    ///     werewolf.data                    ext4 on the disk labelled werewolf-data
    ///     + data.key in the config         the same inside LUKS2, keyed by it
    ///
    /// So a disk is used only where the command line says one is wanted,
    /// and a disk that is slow to appear, or gone, is not quietly replaced
    /// by RAM. The disk is found by its label, so its device name may
    /// differ from boot to boot; werewolf.data names the device to format
    /// when there is none yet.
    fn data(m: *Machine) void {
        mkdir("/data", 0o755);
        if (m.victim_dir.len > 0) {
            // On a machine with slots /data is a directory beside them, on a
            // filesystem the kernel repairs as it mounts it: nothing to
            // format, check or label. It takes precedence over any disk.
            const dir = m.fmtZ("{s}/data", .{m.victim_dir});
            mkdir(dir, 0o755);
            if (m.run(&.{ mount_bin, "--bind", dir, "/data" }) and
                m.run(&.{ mount_bin, "-o", "remount,bind,noatime,nosuid,nodev,noexec", "/data" }))
            {
                say("/data is {s}", .{dir});
            } else {
                m.nodata(m.fmt("cannot bind {s}", .{dir}));
            }
            // From here /victim is for looking at. Read-only is a property of
            // the mount, not the filesystem, so /data, bound from it, stays
            // writable. What must write there (slot-keep; slot-update) mounts
            // it again, apart.
            if (m.run(&.{
                mount_bin,
                "-o",
                "remount,bind,ro,nosuid,nodev,noexec",
                "/victim",
            })) say("/victim is read-only", .{});
        } else if (m.cmd.data.len == 0 or m.which("mke2fs") == null) {
            m.mount(&.{
                "-t",
                "tmpfs",
                "-o",
                "size=25%,nosuid,nodev,noexec,mode=0755",
                "tmpfs",
                "/data",
            });
            say("/data is RAM, capped at 25%", .{});
        } else {
            var why: []const u8 = "";
            if (m.dataHome(&why)) |what| {
                _ = linux.fchmodat(linux.AT.FDCWD, "/data", 0o755);
                say("/data is {s}", .{what});
            } else m.nodata(why);
        }
        // /data holds /data/svc/<service>, which each service makes for
        // itself, and /data/home/<user> for people. The only person init
        // creates is the NoCloud user (Lima's).
        if (m.nocloud_user.len > 0 and !exists("/run/werewolf/nodata")) {
            const home = m.fmtZ("/data/home/{s}", .{m.nocloud_user});
            m.mkdirAll(home);
            if (lookupIds(
                m.read("/run/werewolf/passwd"),
                m.nocloud_user,
            )) |ids| _ = linux.fchownat(linux.AT.FDCWD, home, ids.uid, ids.gid, 0);
            _ = linux.fchmodat(linux.AT.FDCWD, home, 0o700);
        }
        // The key now lives in the kernel's dm table. No service needs it,
        // and the config directory is the one place a service would look.
        _ = linux.unlink("/run/config/data.key");
    }

    /// The form's disk on /data; what it is and where, as said on the
    /// console, or null with why set.
    fn dataHome(m: *Machine, why: *[]const u8) ?[]const u8 {
        const blkid_bin = m.which("blkid") orelse {
            why.* = "no blkid, so no telling a blank disk from one in use";
            return null;
        };
        const key = "/run/config/data.key";
        const key_len = m.read(key).len;
        const crypt = if (key_len == 0) null else m.which("cryptsetup") orelse {
            why.* = "data.key is in the config, and there is no cryptsetup to use it";
            return null;
        };
        const want: []const u8 = if (crypt != null) "crypto_LUKS" else "ext4";
        var fresh = false;

        // Two disks with the label leave no telling which is /data: an
        // attached one could take its place.
        const labelled = m.blkidAll(&.{ "-o", "device", "-t", "LABEL=" ++ label });
        if (std.mem.findScalar(u8, labelled, '\n') != null) {
            why.* = m.fmt(
                "more than one disk is labelled {s}: {s}",
                .{ label, std.mem.replaceOwned(u8, m.gpa, labelled, "\n", " ") catch labelled },
            );
            return null;
        }
        var src = labelled;
        if (src.len > 0) {
            const have = m.blkid(&.{ "-p", "-o", "value", "-s", "TYPE", src });
            if (!std.mem.eql(u8, have, want)) {
                why.* = m.fmt(
                    "{s} is {s}; {s} data.key in the config, this machine wants {s}",
                    .{ src, have, if (crypt != null) "with" else "without", want },
                );
                return null;
            }
        } else {
            const d = m.cmd.data;
            src = m.fmt(
                "/dev/{s}",
                .{if (std.mem.startsWith(u8, d, "/dev/")) d["/dev/".len..] else d},
            );
            if (!isBlockDevice(m.z(src))) {
                why.* = m.fmt("werewolf.data: no device {s}", .{src});
                return null;
            }
            if (hasUstar(m.z(src))) {
                why.* = m.fmt("werewolf.data: {s} holds a config tar", .{src});
                return null;
            }
            if (m.runQuiet(&.{ blkid_bin, "-c", "/dev/null", "-p", src })) {
                why.* = m.fmt("werewolf.data: {s} is not blank", .{src});
                return null;
            }
            fresh = true;
        }

        var fs = src;
        if (crypt) |cryptsetup| {
            // No udev here: libdevmapper must make /dev/mapper nodes itself,
            // here and in /etc/runit/3, which closes the volume and inherits
            // this environment through fence and runit.
            m.env.put("DM_DISABLE_UDEV", "1") catch {};
            mkdir("/run/cryptsetup", 0o700);
            // The key is random, so a slow KDF adds nothing; argon2id's
            // default would spend up to 1 GiB and two seconds every boot.
            const open = [_][]const u8{
                cryptsetup,
                "open",
                "--key-file",
                key,
                "--perf-no_read_workqueue",
                "--perf-no_write_workqueue",
                src,
                "data",
            };
            if (fresh and key_len < min_data_key) {
                why.* = m.fmt(
                    "data.key is {d} bytes; LUKS2 is made only with {d} or more random bytes",
                    .{ key_len, min_data_key },
                );
                return null;
            }
            if (!fresh and key_len < min_data_key) say(
                "data.key is only {d} bytes: a disk copied from this one could be opened by " ++
                    "guessing it; make a new disk with {d} random bytes or more",
                .{ key_len, min_data_key },
            );
            if (fresh) {
                say("making LUKS2 on {s}", .{src});
                if (!m.run(&.{
                    cryptsetup,
                    "luksFormat",
                    "-q",
                    "--type",
                    "luks2",
                    "--label",
                    label,
                    "--pbkdf",
                    "pbkdf2",
                    "--pbkdf-force-iterations",
                    "1000",
                    "--key-file",
                    key,
                    src,
                }) or
                    !m.run(&open))
                {
                    why.* = m.fmt("cannot make LUKS2 on {s}", .{src});
                    return null;
                }
            } else if (!m.runQuiet(&open)) {
                why.* = m.fmt("data.key does not open {s}", .{src});
                return null;
            }
            fs = "/dev/mapper/data";
        }

        // Inside LUKS the filesystem goes unlabelled: the label belongs to
        // the disk, and two devices answering to it would make the search
        // ambiguous. -F: the device is blank as far as blkid can tell, or a
        // LUKS volume made a moment ago, so a stale signature deeper in is no
        // reason to stop. ^orphan_file: e2fsprogs 1.47 turns it on, and ext4
        // then reads all of it, a block at a time, at every mount (0.2s a
        // boot on GCP's disks); without it, orphans go on the list ext4
        // always kept.
        if (fresh) {
            say("formatting {s}", .{fs});
            const mke2fs = m.which("mke2fs").?;
            const ok = if (crypt != null)
                m.run(&.{ mke2fs, "-q", "-F", "-t", "ext4", "-m", "0", "-O", "^orphan_file", fs })
            else
                m.run(&.{
                    mke2fs, "-q",           "-F", "-t",  "ext4", "-m", "0",
                    "-O",   "^orphan_file", "-L", label, fs,
                });
            if (!ok) {
                why.* = m.fmt("mke2fs failed on {s}", .{fs});
                return null;
            }
        } else {
            // -p repairs only what is safe without a person. Anything more
            // is theirs to decide, with the disk attached where there are
            // tools.
            const rc = m.exitCode(&.{ m.which("e2fsck") orelse "e2fsck", "-p", fs });
            if (rc >= 4) {
                why.* = m.fmt("e2fsck -p will not repair {s} (exit {d})", .{ fs, rc });
                return null;
            }
        }
        if (!m.run(&.{
            mount_bin,
            "-t",
            "ext4",
            "-o",
            "noatime,nosuid,nodev,noexec",
            fs,
            "/data",
        })) {
            why.* = m.fmt("cannot mount {s}", .{fs});
            return null;
        }
        return m.fmt("{s} on {s}", .{ want, src });
    }

    fn nodata(m: *Machine, why: []const u8) void {
        say("{s}; /data is unavailable", .{why});
        m.write("/run/werewolf/nodata", m.fmt("{s}\n", .{why}), 0o644);
        m.mount(&.{ "-t", "tmpfs", "-o", "ro,nosuid,nodev,noexec,mode=0755", "tmpfs", "/data" });
    }

    // --- running programs ----------------------------------------------------

    /// werewolf's mount, which says what went wrong itself; the boot goes on.
    fn mount(m: *Machine, args: []const []const u8) void {
        const argv = std.mem.concat(m.gpa, []const u8, &.{ &.{mount_bin}, args }) catch return;
        _ = m.run(argv);
    }

    fn run(m: *Machine, argv: []const []const u8) bool {
        return m.spawn(argv, false) == 0;
    }

    /// As run, with the program's own complaints silenced: for probes, whose
    /// failure is an answer.
    fn runQuiet(m: *Machine, argv: []const []const u8) bool {
        return m.spawn(argv, true) == 0;
    }

    fn exitCode(m: *Machine, argv: []const []const u8) u32 {
        return m.spawn(argv, true);
    }

    /// name's path in PATH, as the shell's command -v finds it. Programs
    /// run by their full path: spawn would resolve a bare name against
    /// init's own environment, and the kernel gives it no PATH.
    fn which(m: *Machine, name: []const u8) ?[:0]const u8 {
        var dirs = std.mem.tokenizeScalar(u8, path_env, ':');
        while (dirs.next()) |dir| {
            const path = m.fmtZ("{s}/{s}", .{ dir, name });
            if (executable(path)) return path;
        }
        return null;
    }

    /// argv's exit code, or 255 if it did not run or was killed.
    fn spawn(m: *Machine, argv: []const []const u8, quiet: bool) u32 {
        var child = std.process.spawn(m.io, .{
            .argv = argv,
            .environ_map = &m.env,
            .stdin = .ignore,
            .stdout = if (quiet) .ignore else .inherit,
            .stderr = if (quiet) .ignore else .inherit,
        }) catch return 255;
        const term = child.wait(m.io) catch return 255;
        return switch (term) {
            .exited => |code| code,
            else => 255,
        };
    }

    /// blkid's answer, trimmed, or "": the device, or the value asked for.
    fn blkid(m: *Machine, args: []const []const u8) []const u8 {
        return firstLine(m.blkidAll(args));
    }

    /// blkid's whole answer, one device or value a line, trimmed, or "".
    fn blkidAll(m: *Machine, args: []const []const u8) []const u8 {
        const argv = std.mem.concat(
            m.gpa,
            []const u8,
            &.{ &.{ m.which("blkid") orelse return "", "-c", "/dev/null" }, args },
        ) catch return "";
        const res = std.process.run(
            m.gpa,
            m.io,
            .{ .argv = argv, .environ_map = &m.env },
        ) catch return "";
        return switch (res.term) {
            .exited => |code| if (code == 0) trim(res.stdout) else "",
            else => "",
        };
    }

    // --- files ---------------------------------------------------------------

    fn isMounted(m: *Machine, point: []const u8) bool {
        return m.mountSource(point) != null;
    }

    /// What is mounted on point, as the kernel's mount table names it, or
    /// null if nothing is.
    fn mountSource(m: *Machine, point: []const u8) ?[]const u8 {
        var it = std.mem.tokenizeScalar(u8, m.read("/proc/self/mounts"), '\n');
        while (it.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            const source = f.next() orelse continue;
            if (std.mem.eql(u8, f.next() orelse continue, point)) return source;
        }
        return null;
    }

    /// path, read to its end, or "" (procfs and sysfs report a size of 0).
    fn read(m: *Machine, path: []const u8) []const u8 {
        var f = Dir.cwd().openFile(m.io, path, .{}) catch return "";
        defer f.close(m.io);
        var buf: [4096]u8 = undefined;
        var r = f.readerStreaming(m.io, &buf);
        return r.interface.allocRemaining(m.gpa, .limited(1 << 20)) catch "";
    }

    /// text to path, with mode; a failure is said.
    fn write(m: *Machine, path: []const u8, text: []const u8, mode: u32) void {
        Dir.cwd().writeFile(
            m.io,
            .{ .sub_path = path, .data = text, .flags = .{ .permissions = .fromMode(mode) } },
        ) catch |err|
            return say("{s}: {s}", .{ path, @errorName(err) });
        _ = linux.fchmodat(linux.AT.FDCWD, m.z(path), mode);
    }

    fn append(m: *Machine, path: []const u8, text: []const u8) void {
        var f = Dir.cwd().openFile(
            m.io,
            path,
            .{ .mode = .write_only },
        ) catch |err| return say("{s}: {s}", .{ path, @errorName(err) });
        defer f.close(m.io);
        const end = f.length(m.io) catch return;
        f.writePositionalAll(
            m.io,
            text,
            end,
        ) catch |err| say("{s}: {s}", .{ path, @errorName(err) });
    }

    /// The names in dir, sorted, as the shell's glob gives them.
    fn list(m: *Machine, dir: []const u8) []const []const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        var d = Dir.cwd().openDir(m.io, dir, .{ .iterate = true }) catch return out.items;
        defer d.close(m.io);
        var it = d.iterate();
        while (it.next(m.io) catch null) |e| {
            if (e.name[0] == '.') continue;
            out.append(m.gpa, m.gpa.dupe(u8, e.name) catch continue) catch continue;
        }
        std.mem.sort([]const u8, out.items, {}, lessString);
        return out.items;
    }

    fn mkdirAll(m: *Machine, path: [:0]const u8) void {
        Dir.cwd().createDirPath(m.io, path) catch {};
        _ = linux.fchmodat(linux.AT.FDCWD, path, 0o700);
    }

    fn fmt(m: *Machine, comptime f: []const u8, args: anytype) []const u8 {
        return m.gpa.print(f, args) catch "";
    }

    fn fmtZ(m: *Machine, comptime f: []const u8, args: anytype) [:0]const u8 {
        return m.gpa.printSentinel(f, args, 0) catch "";
    }

    fn z(m: *Machine, s: []const u8) [:0]const u8 {
        return m.gpa.dupeSentinel(u8, s, 0) catch "";
    }
};

/// What closes doors root could use against the running kernel or another
/// process, and what an ordinary user could use against root. Lockdown,
/// raised before, refuses kexec and /dev/mem. Yama's ptrace scope 3 stops
/// any process writing into another, root's included, and cannot be
/// lowered; memfds can no longer be executed, though root may lower that
/// one. The rest hide kernel pointers and the log, keep BPF to root, stop
/// forwarding, and close user namespaces (a private mount namespace would let
/// a user mount its own tmpfs without noexec) and the symlink, hardlink,
/// FIFO and file tricks the kernel refuses in sticky directories such as
/// /tmp only when asked. Root could undo these; no one else can. io_uring,
/// a large kernel interface nothing here uses, is off; the magic SysRq keys
/// are off (stage0's deadman writes /proc/sysrq-trigger, which they do not
/// govern); ICMP redirects are neither taken nor sent (and, per interface,
/// in kernel(), above); packets from impossible addresses are logged; pings
/// to a broadcast address and bogus ICMP errors are ignored, and a forged
/// reset cannot cut short a closing connection (RFC 1337). Programs' addresses
/// are randomized as far as the kernel allows (4K pages, 48-bit addresses),
/// the first 64 KiB cannot be mapped, the filters any user may install are
/// compiled with their constants blinded, and an oops panics, so a kernel
/// a failed exploit left wrong reboots rather than runs on; kernel.panic,
/// below, makes the panic a reboot. None of it costs a program anything.
/// See docs/security.md.
const sysctls = [_][2][]const u8{
    .{ "vm/mmap_rnd_bits", switch (builtin.cpu.arch) {
        .aarch64 => "33",
        .x86_64 => "32",
        else => @compileError("init runs on aarch64 and x86_64"),
    } },
    .{ "vm/mmap_min_addr", "65536" },
    .{ "net/core/bpf_jit_harden", "1" },
    .{ "kernel/panic_on_oops", "1" },
    .{ "kernel/kptr_restrict", "2" },
    .{ "kernel/dmesg_restrict", "1" },
    .{ "kernel/unprivileged_bpf_disabled", "1" },
    .{ "net/ipv4/ip_forward", "0" },
    .{ "kernel/yama/ptrace_scope", "3" },
    .{ "vm/memfd_noexec", "2" },
    .{ "user/max_user_namespaces", "0" },
    .{ "fs/protected_symlinks", "1" },
    .{ "fs/protected_hardlinks", "1" },
    .{ "fs/protected_fifos", "2" },
    .{ "fs/protected_regular", "2" },
    .{ "kernel/io_uring_disabled", "2" },
    .{ "kernel/sysrq", "0" },
    // No program for the kernel to start on every device event: it would
    // run outside the seal (see seal()). An empty line empties it.
    .{ "kernel/hotplug", "\n" },
    .{ "net/ipv4/conf/all/log_martians", "1" },
    .{ "net/ipv4/conf/default/log_martians", "1" },
    .{ "net/ipv4/icmp_echo_ignore_broadcasts", "1" },
    .{ "net/ipv4/icmp_ignore_bogus_error_responses", "1" },
    .{ "net/ipv4/tcp_rfc1337", "1" },
};

// --- the seal --------------------------------------------------------------------

/// The seal (docs/design/lockdown.md) denies by default, in promises
/// (docs/design/pledge.md, System calls: promises): every process the
/// machine will run may make the calls of the promises werewolf's own
/// programs make (seal_lib.base) and of every promise the image's services
/// make, which the build gathers from their service files' `pledge` lines
/// into /usr/share/werewolf/pledge. leash then holds each service to its
/// own. The rest go to seal-watch (cmd/seal-watch), which refuses them as
/// if the kernel had no such call and says so once each, with the promise
/// that would allow it; or, on a DEV=1 build booted with
/// werewolf.seal=learn, allows and records them. What no promise brings
/// goes to seal-watch too, so an attempt by a program the machine's
/// promises alone bind is seen; a leashed service's own filter refuses it
/// first, and the kernel takes that ENOSYS over the listener, unseen.
const never = seal_lib.never;

/// What policy_path says: the mode, and the promises the seal allows.
fn policyText(gpa: Allocator, learn: bool, promises: seal_lib.Set) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.print(gpa, "mode {s}\npromises", .{if (learn) "learn" else "enforce"});
    var it = promises.iterator();
    while (it.next()) |p| try out.print(gpa, " {s}", .{@tagName(p)});
    try out.append(gpa, '\n');
    return out.items;
}

/// Capabilities no process needs once init hands over, dropped from the
/// bounding set, so not even root gets them back before a reboot: code in
/// the kernel (SYS_MODULE, BPF, PERFMON), hardware and ports (SYS_RAWIO),
/// other processes (SYS_PTRACE), device files (MKNOD), and what nothing here
/// uses. fence drops NET_ADMIN and NET_RAW after it sets the network
/// policy, unless the form allows them. SYSLOG stays, for dmesg.
const dropped_caps = [_]struct { name: []const u8, n: u6 }{
    .{ .name = "linux_immutable", .n = 9 },
    .{ .name = "sys_module", .n = 16 },
    .{ .name = "sys_rawio", .n = 17 },
    .{ .name = "sys_ptrace", .n = 19 },
    .{ .name = "sys_pacct", .n = 20 },
    .{ .name = "sys_time", .n = 25 },
    .{ .name = "mknod", .n = 27 },
    .{ .name = "audit_control", .n = 30 },
    .{ .name = "mac_override", .n = 32 },
    .{ .name = "mac_admin", .n = 33 },
    .{ .name = "wake_alarm", .n = 35 },
    .{ .name = "block_suspend", .n = 36 },
    .{ .name = "perfmon", .n = 38 },
    .{ .name = "bpf", .n = 39 },
    .{ .name = "checkpoint_restore", .n = 40 },
};

/// The capabilities a program the kernel starts itself may have: a
/// usermode helper, which kthreadd starts, not PID 1, so neither the seal's
/// filter nor its bounding set reach it. Root could name one (a core
/// pattern of `|PROGRAM`, kernel.modprobe, kernel.hotplug) and have it run
/// with every capability, outside the seal. Only CAP_SYS_BOOT is left, for
/// the kernel's own orderly poweroff. The kernel lets these only fall, and
/// only for a holder of CAP_SYS_MODULE, which the seal then takes.
const helper_caps: u64 = 1 << 22; // CAP_SYS_BOOT

/// "LOW HIGH": a capability set as kernel.usermodehelper.bset reads it.
fn capWords(buf: []u8, set: u64) []const u8 {
    return std.mem.print(
        buf,
        "{d} {d}",
        .{ @as(u32, @truncate(set)), @as(u32, @truncate(set >> 32)) },
    ) catch unreachable;
}

/// seal-watch, started before the seal so it is not under it, with one end
/// of a socket as its stdin, over which it is sent the seal's listener; the
/// other end, or null if it cannot be started. Raw calls only between fork
/// and exec: this process may have threads.
fn startWatch() ?i32 {
    const path = "/usr/lib/werewolf/seal-watch";
    if (!executable(path)) return null;
    var sv: [2]i32 = undefined;
    if (linux.errno(linux.socketpair(
        linux.AF.UNIX,
        linux.SOCK.SEQPACKET | linux.SOCK.CLOEXEC,
        0,
        &sv,
    )) != .SUCCESS) return null;
    const argv: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{path};
    const envp: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{};
    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return null;
    if (pid == 0) {
        _ = linux.dup2(sv[1], 0);
        _ = linux.execve(path, argv, envp);
        linux.exit_group(127);
    }
    _ = linux.close(sv[1]);
    return sv[0];
}

/// Install the seal on PID 1, which every process inherits and none, root
/// included, can remove until the machine reboots: the helpers' bounding
/// set, PID 1's, then the filter. PID 1 holds CAP_SYS_ADMIN, so it needs no
/// no_new_privs, which would bind every program after it. Any step that
/// fails is an error; a capability the kernel does not know (EINVAL) is
/// one it cannot grant.
fn seal(m: *Machine) !void {
    // Learning: what the promises do not allow, seal-watch allows and
    // records, with the promise that would, so a service's author learns
    // what its pledge lacks. Only on a DEV=1 build, never released;
    // anywhere else the word is ignored.
    const learn = std.mem.eql(u8, m.cmd.seal, "learn") and exists("/usr/share/werewolf/dev");
    if (m.cmd.seal.len > 0 and
        !learn) say("werewolf.seal={s} ignored: only a DEV=1 build learns", .{m.cmd.seal});
    var bad: []const u8 = "";
    const pledged = seal_lib.parse(m.read("/usr/share/werewolf/pledge"), &bad) catch |err| {
        say("/usr/share/werewolf/pledge: {s}: {s}", .{ bad, @errorName(err) });
        return err;
    };
    const promises = seal_lib.base.unionWith(pledged);
    var buf: [32]u8 = undefined;
    // The bounding set for the programs the kernel starts itself, which the
    // seccomp filter does not reach. On real hardware /proc/sys is writable --
    // init has just mounted /proc -- so a failure here is real and fatal. In a
    // container /proc/sys is read-only (EROFS) and these are the host's to set,
    // not ours, and the kernel's helpers never run in the container's
    // namespaces anyway; tolerate that one case, and that one alone, so the
    // read-only mount cannot be forged into skipping the limit on a real boot.
    for ([_][:0]const u8{
        "/proc/sys/kernel/usermodehelper/bset",
        "/proc/sys/kernel/usermodehelper/inheritable",
    }, [_]u64{ helper_caps, 0 }) |path, set| {
        switch (writeErrno(path, capWords(&buf, set))) {
            .SUCCESS => {},
            .ROFS => {
                say(
                    "usermodehelper caps left to the host: /proc/sys is read-only (a container)",
                    .{},
                );
                break;
            },
            else => |e| {
                say("usermodehelper caps: {t}", .{e});
                return error.UsermodeHelperCaps;
            },
        }
    }
    mkdir("/run/werewolf/seal", 0o755);
    const watch = startWatch();
    if (watch == null) say("no seal-watch: unlisted calls are refused unsaid", .{});
    const PR_CAPBSET_DROP = 24;
    var caps: usize = 0;
    for (dropped_caps) |c| {
        const rc = linux.prctl(PR_CAPBSET_DROP, c.n, 0, 0, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => caps += 1,
            .INVAL => {},
            else => |e| {
                say("cap_{s} not dropped: {t}", .{ c.name, e });
                return error.BoundingSet;
            },
        }
    }
    var filter_buf: [seal_lib.max_filter]seal_lib.Filter = undefined;
    const filter = seal_lib.buildFilter(&filter_buf, promises, false);
    const listener = seal_lib.install(filter, true) catch |err| {
        say("seccomp: {s}", .{@errorName(err)});
        return err;
    };
    // The listener goes to seal-watch alone. Once no one holds it, the
    // kernel refuses every call the promises do not allow, itself.
    if (watch) |sock| {
        if (!seal_lib.sendListener(sock, listener, if (learn) "l" else "e"))
            say("seal-watch did not take the listener: unlisted calls are refused unsaid", .{});
        _ = linux.close(sock);
    }
    _ = linux.close(listener);
    m.write(seal_lib.policy_path, policyText(m.gpa, learn, promises) catch "", 0o644);
    say(
        "sealed: {d} promises; every other call {s}; {d} capabilities dropped; " ++
            "other architectures' calls fatal",
        .{ promises.count(), if (learn) "allowed and recorded" else "refused", caps },
    );
}

/// What a config tar's extraction may do: write beneath /run/config, which
/// dir names, and nothing else; root's uid with no capabilities, so no
/// other file it could not reach as an owner; no socket, process or mount
/// call, refused as if the kernel had none.
fn confineExtract(dir: i32) !void {
    try sandbox.keepOnly(0);
    try sandbox.landlock(&.{.{ .fd = dir, .access = sandbox.own_dir }}, &.{});
    var buf: [seal_lib.max_filter]seal_lib.Filter = undefined;
    const filter = seal_lib.buildFilter(&buf, .initMany(&.{ .stdio, .rpath, .wpath }), true);
    _ = seal_lib.install(filter, false) catch {
        sandbox.failed = "seccomp";
        return error.SystemCall;
    };
}

// --- pure functions, tested below ----------------------------------------------

const Cmdline = struct {
    ip: []const u8 = "",
    gw: []const u8 = "",
    dns: []const u8 = "",
    mac: []const u8 = "",
    data: []const u8 = "",
    victim: []const u8 = "",
    grubenv: []const u8 = "",
    seal: []const u8 = "",
};

fn parseCmdline(text: []const u8) Cmdline {
    var c: Cmdline = .{};
    var it = std.mem.tokenizeAny(u8, text, " \t\n");
    while (it.next()) |arg| {
        inline for (@typeInfo(Cmdline).@"struct".field_names) |name| {
            const prefix = "werewolf." ++ name ++ "=";
            if (std.mem.startsWith(u8, arg, prefix)) @field(c, name) = arg[prefix.len..];
        }
    }
    return c;
}

const NoCloud = struct { user: []const u8 = "", uid: []const u8 = "1000", keys: []const u8 = "" };

const LimaFile = struct { id: []const u8, name: []const u8 };

fn readLimaData(gpa: Allocator, io: Io, cidata: Dir, files: []const LimaFile) ![]const []const u8 {
    var payloads = try cidata.openDir(io, "provision.data", .{ .follow_symlinks = false });
    defer payloads.close(io);
    const values = try gpa.alloc([]const u8, files.len);
    for (files, values) |file, *value|
        value.* = try readLimaFile(gpa, io, payloads, file.id);
    return values;
}

fn readLimaFile(gpa: Allocator, io: Io, dir: Dir, name: []const u8) ![]const u8 {
    // cidata is read-only. Refuse special files before opening: a FIFO
    // could otherwise wait forever for a writer before f.stat sees it.
    const entry = try dir.statFile(io, name, .{ .follow_symlinks = false });
    if (entry.kind != .file or entry.size > 32 * 1024) return error.InvalidLimaDataFile;
    var f = try dir.openFile(io, name, .{ .follow_symlinks = false });
    defer f.close(io);
    const st = try f.stat(io);
    if (st.kind != .file or st.size > 32 * 1024) return error.InvalidLimaDataFile;
    var buf: [4096]u8 = undefined;
    var reader = f.readerStreaming(io, &buf);
    return reader.interface.allocRemaining(gpa, .limited(32 * 1024));
}

test "Lima data is bounded and never follows links" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const files = [_]LimaFile{.{ .id = "00000000", .name = "service/key" }};
    try tmp.dir.createDir(io, "provision.data", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "provision.data/00000000", .data = "private\n" });
    const values = try readLimaData(arena.allocator(), io, tmp.dir, &files);
    try std.testing.expectEqualStrings("private\n", values[0]);
    const large = try arena.allocator().alloc(u8, 32 * 1024 + 1);
    @memset(large, 'x');
    try tmp.dir.writeFile(io, .{ .sub_path = "provision.data/00000000", .data = large });
    try std.testing.expectError(
        error.InvalidLimaDataFile,
        readLimaData(arena.allocator(), io, tmp.dir, &files),
    );
    try tmp.dir.deleteFile(io, "provision.data/00000000");
    try tmp.dir.writeFile(io, .{ .sub_path = "victim", .data = "must not be imported" });
    try tmp.dir.symLink(io, "../victim", "provision.data/00000000", .{});
    if (readLimaData(arena.allocator(), io, tmp.dir, &files)) |_|
        return error.FollowedSymlink
    else |_| {}
    try tmp.dir.deleteFile(io, "provision.data/00000000");
    try tmp.dir.deleteDir(io, "provision.data");
    try tmp.dir.createDir(io, "other", .default_dir);
    try std.testing.expectError(
        error.InvalidLimaDataFile,
        readLimaFile(arena.allocator(), io, tmp.dir, "other"),
    );
    try tmp.dir.writeFile(io, .{ .sub_path = "other/00000000", .data = "outside" });
    try tmp.dir.symLink(io, "other", "provision.data", .{});
    if (readLimaData(arena.allocator(), io, tmp.dir, &files)) |_|
        return error.FollowedSymlink
    else |_| {}
}

fn limaDataFiles(gpa: Allocator, env: []const u8) ![]const LimaFile {
    var files: std.ArrayList(LimaFile) = .empty;
    var lines = std.mem.splitScalar(u8, env, '\n');
    while (lines.next()) |line| {
        const prefix = "LIMA_CIDATA_DATAFILE_";
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        const rest = line[prefix.len..];
        if (rest.len < 14 or !std.mem.startsWith(u8, rest[8..], "_PATH=")) continue;
        const id = rest[0..8];
        for (id) |c| if (!std.ascii.isDigit(c)) return error.InvalidLimaDataId;
        const path = std.mem.trimEnd(u8, rest[14..], "\r");
        if (!std.mem.startsWith(u8, path, "/run/config/")) continue;
        const relative = path["/run/config/".len..];
        for (relative) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and
            c != '.' and c != '/')
            return error.InvalidLimaConfigPath;
        const name = safeName(relative) orelse return error.InvalidLimaConfigPath;
        if (name.len == 0 or !std.mem.eql(u8, name, relative)) return error.InvalidLimaConfigPath;
        if (files.items.len == 32) return error.TooManyLimaConfigFiles;
        for (files.items) |f| {
            if (std.mem.eql(u8, f.id, id) or
                std.mem.eql(u8, f.name, name)) return error.DuplicateLimaConfigFile;
            // Prevent file/directory conflicts between destinations.
            if ((std.mem.startsWith(u8, name, f.name) and name.len > f.name.len and
                name[f.name.len] == '/') or
                (std.mem.startsWith(u8, f.name, name) and f.name.len > name.len and
                    f.name[name.len] == '/'))
                return error.ConflictingLimaConfigPaths;
        }
        try files.append(gpa, .{ .id = id, .name = name });
    }
    return files.items;
}

test "Lima data imports only plain config paths" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const files = try limaDataFiles(gpa,
        \\LIMA_CIDATA_DATAFILE_00000000_PATH=/run/config/bastion/settings.json
        \\LIMA_CIDATA_DATAFILE_00000001_PATH=/etc/ssh/sshd_config
        \\LIMA_CIDATA_DATAFILE_00000002_PATH=/run/config/tailscale/auth_key
        \\LIMA_CIDATA_YQ_PROVISION_00000003_PATH=/run/config/ignored
        \\LIMA_CIDATA_DATAFILE_00000004_OWNER=root:root
    );
    try std.testing.expectEqual(@as(usize, 2), files.len);
    try std.testing.expectEqualStrings("00000000", files[0].id);
    try std.testing.expectEqualStrings("bastion/settings.json", files[0].name);
    for ([_][]const u8{
        "/run/config/../etc/shadow",
        "/run/config/a//b",
        "/run/config/",
        "/run/config/a;echo",
    }) |path| {
        const line = try gpa.print("LIMA_CIDATA_DATAFILE_00000000_PATH={s}", .{path});
        try std.testing.expectError(error.InvalidLimaConfigPath, limaDataFiles(gpa, line));
    }
    try std.testing.expectError(
        error.InvalidLimaDataId,
        limaDataFiles(gpa, "LIMA_CIDATA_DATAFILE_../../.._PATH=/run/config/key"),
    );
    try std.testing.expectError(error.DuplicateLimaConfigFile, limaDataFiles(gpa,
        \\LIMA_CIDATA_DATAFILE_00000000_PATH=/run/config/key
        \\LIMA_CIDATA_DATAFILE_00000001_PATH=/run/config/key
    ));
    try std.testing.expectError(error.ConflictingLimaConfigPaths, limaDataFiles(gpa,
        \\LIMA_CIDATA_DATAFILE_00000000_PATH=/run/config/key
        \\LIMA_CIDATA_DATAFILE_00000001_PATH=/run/config/key/child
    ));
}

/// The first user's name and uid in a cloud-config, quotes dropped, and
/// every ssh public key in it, one a line.
fn parseNoCloud(gpa: Allocator, text: []const u8) !NoCloud {
    var nc: NoCloud = .{};
    var user_found = false;
    var uid_found = false;
    var keys: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const t = std.mem.trimStart(u8, line, " ");
        if (!user_found and std.mem.startsWith(u8, t, "-")) {
            const rest = std.mem.trimStart(u8, t[1..], " ");
            if (std.mem.startsWith(u8, rest, "name:")) {
                nc.user = try std.mem.replaceOwned(u8, gpa, lastField(rest), "\"", "");
                user_found = true;
            }
        }
        if (!uid_found and std.mem.startsWith(u8, t, "uid:")) {
            nc.uid = try std.mem.replaceOwned(u8, gpa, lastField(t), "\"", "");
            uid_found = true;
        }
        try sshKeys(gpa, line, &keys);
    }
    nc.keys = keys.items;
    return nc;
}

const key_types = [_][]const u8{ "ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-nistp", "sk-" };

/// Every ssh public key on line, one a line into out: a type, a space, the
/// base64 body, and an optional comment to the end of the line or a quote.
fn sshKeys(gpa: Allocator, line: []const u8, out: *std.ArrayList(u8)) !void {
    var i: usize = 0;
    while (i < line.len) {
        const start = i;
        const kind_end = keyTypeEnd(line[i..]) orelse {
            i += 1;
            continue;
        };
        var j = start + kind_end;
        const body = j;
        while (j < line.len and isBase64(line[j])) j += 1;
        if (j == body) {
            i += 1;
            continue;
        }
        if (j < line.len and line[j] == ' ') {
            const q = std.mem.findScalarPos(u8, line, j, '"') orelse line.len;
            j = q;
        }
        try out.print(gpa, "{s}\n", .{std.mem.trimEnd(u8, line[start..j], " \r")});
        i = j;
    }
}

/// Where the key type at the start of s ends, with its space: ssh-ed25519,
/// ssh-rsa, ecdsa-sha2-nistpN, sk-...@openssh.com.
fn keyTypeEnd(s: []const u8) ?usize {
    if (std.mem.startsWith(u8, s, "ssh-ed25519 ")) return "ssh-ed25519 ".len;
    if (std.mem.startsWith(u8, s, "ssh-rsa ")) return "ssh-rsa ".len;
    if (std.mem.startsWith(u8, s, "ecdsa-sha2-nistp")) {
        var k: usize = "ecdsa-sha2-nistp".len;
        while (k < s.len and std.ascii.isDigit(s[k])) k += 1;
        if (k == "ecdsa-sha2-nistp".len or k >= s.len or s[k] != ' ') return null;
        return k + 1;
    }
    if (std.mem.startsWith(u8, s, "sk-")) {
        const at = std.mem.indexOf(u8, s, "@openssh.com ") orelse return null;
        for (s[3..at]) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and
            c != '-') return null;
        return at + "@openssh.com ".len;
    }
    return null;
}

fn isBase64(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '+' or c == '/' or c == '=';
}

/// A NoCloud name: [a-z_][a-z0-9_-]{0,31}.
fn isPlainUser(s: []const u8) bool {
    if (s.len == 0 or s.len > 32) return false;
    if (!std.ascii.isLower(s[0]) and s[0] != '_') return false;
    for (s[1..]) |c| if (!std.ascii.isLower(c) and !std.ascii.isDigit(c) and c != '_' and
        c != '-') return false;
    return true;
}

/// A NoCloud uid: 500 to 60000, written plainly, so macOS's users (501
/// and up, which Lima passes on) fit and root's never does. Taking a system
/// account's is stopped by idInUse, not by the range.
fn isPlainUid(s: []const u8) bool {
    if (s.len == 0 or s.len > 5 or s[0] == '0') return false;
    for (s) |c| if (!std.ascii.isDigit(c)) return false;
    const n = std.fmt.parseInt(u32, s, 10) catch return false;
    return n >= 500 and n <= 60000;
}

/// Whether an /etc/passwd- or /etc/group-like file already has id as an
/// entry's third field: its uid, or its gid.
fn idInUse(text: []const u8, id: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        _ = f.next();
        _ = f.next();
        if (std.mem.eql(u8, f.next() orelse continue, id)) return true;
    }
    return false;
}

fn isHostname(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '.') return false;
    return s[0] != '-' and s[0] != '.';
}

/// Whether an /etc/passwd-like file has an entry for name.
fn hasEntry(text: []const u8, name: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, name) and line.len > name.len and
            line[name.len] == ':') return true;
    }
    return false;
}

const Ids = struct { uid: u32, gid: u32 };

/// name's uid and gid in an /etc/passwd.
fn lookupIds(passwd: []const u8, name: []const u8) ?Ids {
    var it = std.mem.tokenizeScalar(u8, passwd, '\n');
    while (it.next()) |line| {
        var f = std.mem.splitScalar(u8, line, ':');
        if (!std.mem.eql(u8, f.next() orelse continue, name)) continue;
        _ = f.next() orelse return null;
        const uid = std.fmt.parseInt(u32, f.next() orelse return null, 10) catch return null;
        const gid = std.fmt.parseInt(u32, f.next() orelse return null, 10) catch return null;
        return .{ .uid = uid, .gid = gid };
    }
    return null;
}

/// A tar entry's name, made relative and plain: no leading /, no . or ..,
/// no empty parts; "" for the archive's root, ./ itself. null if it cannot
/// be.
fn safeName(name: []const u8) ?[]const u8 {
    var n = name;
    while (std.mem.startsWith(u8, n, "./")) n = n[2..];
    if (std.mem.eql(u8, n, ".")) return "";
    if (n.len > 0 and n[0] == '/') return null;
    n = std.mem.trimEnd(u8, n, "/");
    if (n.len == 0) return "";
    var parts = std.mem.splitScalar(u8, n, '/');
    while (parts.next()) |p| {
        if (p.len == 0 or std.mem.eql(u8, p, ".") or std.mem.eql(u8, p, "..")) return null;
        for (p) |c| if (c < 0x20 or c == 0x7f) return null;
    }
    return n;
}

/// instance-id's value in a NoCloud meta-data.
fn instanceId(text: []const u8) []const u8 {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (!std.mem.startsWith(u8, line, "instance-id:")) continue;
        var f = std.mem.tokenizeAny(u8, line["instance-id:".len..], " \t\r");
        return f.next() orelse "";
    }
    return "";
}

/// The level in /sys/kernel/security/lockdown: "none [integrity] confidentiality".
fn lockdownLevel(text: []const u8) []const u8 {
    const a = std.mem.findScalar(u8, text, '[') orelse return "unavailable";
    const b = std.mem.findScalarPos(u8, text, a, ']') orelse return "unavailable";
    return text[a + 1 .. b];
}

fn lastField(s: []const u8) []const u8 {
    const t = std.mem.trimEnd(u8, s, " \t\r");
    const i = std.mem.lastIndexOfAny(u8, t, " \t") orelse return t;
    return t[i + 1 ..];
}

fn firstLine(s: []const u8) []const u8 {
    return s[0 .. std.mem.findScalar(u8, s, '\n') orelse s.len];
}

fn firstWord(s: []const u8) []const u8 {
    var it = std.mem.tokenizeAny(u8, s, " \n");
    return it.next() orelse "";
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n");
}

fn orNone(s: []const u8) []const u8 {
    return if (s.len > 0) s else "none";
}

fn lessString(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

// --- the kernel, directly --------------------------------------------------------

fn mkdir(path: [:0]const u8, mode: u32) void {
    _ = linux.mkdir(path, mode);
}

fn exists(path: [:0]const u8) bool {
    return linux.errno(linux.access(path, linux.F_OK)) == .SUCCESS;
}

fn executable(path: [:0]const u8) bool {
    return linux.errno(linux.access(path, linux.X_OK)) == .SUCCESS;
}

fn isBlockDevice(path: [:0]const u8) bool {
    var st: linux.Statx = undefined;
    if (linux.errno(linux.statx(
        linux.AT.FDCWD,
        path,
        0,
        .{ .TYPE = true },
        &st,
    )) != .SUCCESS) return false;
    return st.mode & linux.S.IFMT == linux.S.IFBLK;
}

/// Whether dev holds a tar: "ustar" at byte 257.
fn hasUstar(dev: [:0]const u8) bool {
    const fd = linux.open(dev, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    var magic: [5]u8 = undefined;
    const n = linux.pread(@intCast(fd), &magic, magic.len, 257);
    return linux.errno(n) == .SUCCESS and n == 5 and std.mem.eql(u8, &magic, "ustar");
}

/// Whether dev is an ISO9660 volume labelled cidata (or CIDATA), as a
/// NoCloud seed is: its primary volume descriptor, at 32 KiB, says CD001,
/// and its volume identifier, from byte 40, is the label: padded with
/// spaces, as the standard says, or with NULs, as Lima's and macOS's are.
fn isNoCloud(dev: [:0]const u8) bool {
    const fd = linux.open(dev, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    var pvd: [72]u8 = undefined;
    const n = linux.pread(@intCast(fd), &pvd, pvd.len, 0x8000);
    return linux.errno(n) == .SUCCESS and n == pvd.len and isCidata(&pvd);
}

fn isCidata(pvd: *const [72]u8) bool {
    if (pvd[0] != 1 or !std.mem.eql(u8, pvd[1..6], "CD001")) return false;
    const volume = std.mem.trimEnd(u8, pvd[40..72], " \x00");
    return std.mem.eql(u8, volume, "cidata") or std.mem.eql(u8, volume, "CIDATA");
}

fn writeFile(path: [:0]const u8, data: []const u8) bool {
    return writeErrno(path, data) == .SUCCESS;
}

/// writeFile, but returning why it failed, so a caller can tell a read-only
/// /proc/sys (a container) from a refusal that matters on real hardware.
fn writeErrno(path: [:0]const u8, data: []const u8) linux.E {
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return linux.errno(fd);
    defer _ = linux.close(@intCast(fd));
    const n = linux.write(@intCast(fd), data.ptr, data.len);
    if (linux.errno(n) != .SUCCESS) return linux.errno(n);
    return if (n == data.len) .SUCCESS else .IO;
}

fn say(comptime f: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "werewolf: " ++ f ++ "\n", args) catch return;
    _ = linux.write(1, line.ptr, line.len);
}

/// Where the boot's time went: each phase's name and when it ended, in
/// milliseconds of the boot clock. stage0 hands its own over as
/// WEREWOLF_BOOT, `kernel=225 modules=611 slot=838 root=851`; init adds
/// its own after them.
const Phases = struct {
    names: [max][]const u8 = undefined,
    ends: [max]u64 = undefined,
    len: usize = 0,

    const max = 16;
    const Took = struct { name: []const u8, ms: u64 };

    /// stage0's phases: each a name of lowercase letters and when it ended,
    /// none before the last. The first that is not stops the list.
    fn parse(text: []const u8) Phases {
        var p: Phases = .{};
        var it = std.mem.tokenizeScalar(u8, text, ' ');
        while (it.next()) |word| {
            const eq = std.mem.findScalar(u8, word, '=') orelse break;
            const name = word[0..eq];
            const end = std.fmt.parseInt(u64, word[eq + 1 ..], 10) catch break;
            if (name.len == 0 or name.len > 16) break;
            for (name) |c| if (c < 'a' or c > 'z') return p;
            if (p.len > 0 and end < p.ends[p.len - 1]) break;
            p.add(name, end);
        }
        return p;
    }

    /// A phase that ended at end; past max, nothing.
    fn add(p: *Phases, name: []const u8, end: u64) void {
        if (p.len == max) return;
        p.names[p.len] = name;
        p.ends[p.len] = end;
        p.len += 1;
    }

    /// When the phase name ended, or 0 if there was none.
    fn endOf(p: *const Phases, name: []const u8) u64 {
        for (p.names[0..p.len], p.ends[0..p.len]) |n, e| if (std.mem.eql(u8, n, name)) return e;
        return 0;
    }

    /// How long each phase took: from the end of the one before, or, for the
    /// first, from the boot clock's start.
    fn durations(p: *const Phases, gpa: Allocator) []const Took {
        const out = gpa.alloc(Took, p.len) catch return &.{};
        for (out, 0..) |*t, i| t.* = .{
            .name = p.names[i],
            .ms = p.ends[i] -| if (i == 0) 0 else p.ends[i - 1],
        };
        return out;
    }
};

// --- tests -------------------------------------------------------------------

const testing = std.testing;

test policyText {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const text = try policyText(arena.allocator(), false, .initMany(&.{ .stdio, .inet }));
    try testing.expectEqualStrings("mode enforce\npromises stdio inet\n", text);
}

test capWords {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("4194304 0", capWords(&buf, helper_caps));
    try testing.expectEqualStrings("0 0", capWords(&buf, 0));
    try testing.expectEqualStrings("4294967295 511", capWords(&buf, (1 << 41) - 1));
}

test parseCmdline {
    const c = parseCmdline(
        "console=hvc0 werewolf.ip=10.0.2.15/24 werewolf.gw=10.0.2.2 werewolf.data=vda " ++
            "werewolf.victim=ab:/w werewolf.debug=1\n",
    );
    try testing.expectEqualStrings("10.0.2.15/24", c.ip);
    try testing.expectEqualStrings("10.0.2.2", c.gw);
    try testing.expectEqualStrings("vda", c.data);
    try testing.expectEqualStrings("ab:/w", c.victim);
    try testing.expectEqualStrings("", c.mac);
}

test parseNoCloud {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const ud =
        \\#cloud-config
        \\users:
        \\  - name: "t"
        \\    uid: "501"
        \\    ssh-authorized-keys:
        \\      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc t@mac"
        \\      - ecdsa-sha2-nistp256 AAAAE2VjZHNh= other
        \\  - name: second
        \\    uid: 1002
    ;
    const nc = try parseNoCloud(arena.allocator(), ud);
    try testing.expectEqualStrings("t", nc.user);
    try testing.expectEqualStrings("501", nc.uid);
    try testing.expectEqualStrings(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc t@mac\necdsa-sha2-nistp256 AAAAE2VjZHNh= other\n",
        nc.keys,
    );
    try testing.expect(isPlainUid(nc.uid)); // 501: macOS's first user, through Lima
    const none = try parseNoCloud(arena.allocator(), "#cloud-config\n");
    try testing.expectEqualStrings("1000", none.uid);
    try testing.expectEqualStrings("", none.user);
}

test sshKeys {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var out: std.ArrayList(u8) = .empty;
    try sshKeys(arena.allocator(), "  - sk-ssh-ed25519@openssh.com AAAAGnNr comment here", &out);
    try sshKeys(arena.allocator(), "ssh-rsa AAAAB3Nza", &out);
    try sshKeys(arena.allocator(), "ssh-dss AAAA not ours; ssh-rsa  no-body", &out);
    try testing.expectEqualStrings(
        "sk-ssh-ed25519@openssh.com AAAAGnNr comment here\nssh-rsa AAAAB3Nza\n",
        out.items,
    );
}

test "validation" {
    try testing.expect(isPlainUser("lima"));
    try testing.expect(isPlainUser("_svc-1"));
    try testing.expect(!isPlainUser("Root"));
    try testing.expect(!isPlainUser("a:b"));
    try testing.expect(!isPlainUser("../x"));
    try testing.expect(isPlainUid("1000"));
    try testing.expect(isPlainUid("500"));
    try testing.expect(isPlainUid("60000"));
    try testing.expect(!isPlainUid("499"));
    try testing.expect(!isPlainUid("60001"));
    try testing.expect(!isPlainUid("0"));
    try testing.expect(!isPlainUid("0100"));
    try testing.expect(!isPlainUid("+501"));
    try testing.expect(!isPlainUid("1234567890"));
    try testing.expect(idInUse("root:x:0:0::/root:/bin/sh\n_dhcp:x:501:501::/:/x\n", "501"));
    try testing.expect(idInUse("_update:x:69:\n", "69"));
    try testing.expect(!idInUse("root:x:0:0::/root:/bin/sh\nt:x:5010:5010::/:/x\n", "501"));
    try testing.expect(isHostname("lima-werewolf-demo"));
    try testing.expect(!isHostname("a b"));
    try testing.expect(!isHostname("-x"));
    try testing.expect(hasEntry("root:x:0:0::/root:/bin/sh\nt:x:501:501::/:/x\n", "t"));
    try testing.expect(!hasEntry("tt:x:1:1::/:/x\n", "t"));
    try testing.expectEqual(
        Ids{ .uid = 200, .gid = 201 },
        lookupIds("nginx:x:200:201::/:/x\n", "nginx").?,
    );
}

test safeName {
    try testing.expectEqualStrings("authorized_keys", safeName("./authorized_keys").?);
    try testing.expectEqualStrings("cloudflared/token", safeName("cloudflared/token").?);
    try testing.expectEqualStrings("nginx", safeName("nginx/").?);
    try testing.expectEqual(null, safeName("/etc/passwd"));
    try testing.expectEqual(null, safeName("../x"));
    try testing.expectEqual(null, safeName("a/../../x"));
    try testing.expectEqual(null, safeName("a//b"));
    try testing.expectEqualStrings("", safeName("./").?);
    try testing.expectEqualStrings("", safeName(".").?);
    try testing.expectEqual(null, safeName("/"));
}

test Phases {
    var p = Phases.parse("kernel=225 modules=611 slot=838 root=851");
    p.add("mounts", 900);
    try testing.expectEqual(225, p.endOf("kernel"));
    try testing.expectEqual(0, p.endOf("absent"));
    const took = p.durations(testing.allocator);
    defer testing.allocator.free(took);
    try testing.expectEqual(5, took.len);
    try testing.expectEqualStrings("kernel", took[0].name);
    try testing.expectEqual(225, took[0].ms);
    try testing.expectEqual(386, took[1].ms);
    try testing.expectEqualStrings("mounts", took[4].name);
    try testing.expectEqual(49, took[4].ms);

    // A bad word ends the list; what came before it stays.
    try testing.expectEqual(1, Phases.parse("kernel=225 modules=100").len);
    try testing.expectEqual(1, Phases.parse("kernel=225 Bad=900 root=950").len);
    try testing.expectEqual(1, Phases.parse("kernel=225 root=x").len);
    try testing.expectEqual(1, Phases.parse("kernel=225 \"x\"=900").len);
    try testing.expectEqual(0, Phases.parse("").len);
    try testing.expectEqual(0, Phases.parse("=5").len);

    // Past max, nothing more is kept.
    var full: Phases = .{};
    for (0..Phases.max + 3) |i| full.add("x", i);
    try testing.expectEqual(Phases.max, full.len);
}

test "small parsers" {
    try testing.expectEqualStrings(
        "i-0123",
        instanceId("local-hostname: x\ninstance-id: i-0123\n"),
    );
    try testing.expectEqualStrings(
        "integrity",
        lockdownLevel("none [integrity] confidentiality\n"),
    );
    try testing.expectEqualStrings("12.34", firstWord("12.34 56.78\n"));
}

/// Milliseconds since the kernel started its clock.
fn bootMs() u64 {
    var ts: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.BOOTTIME, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

test isCidata {
    var pvd: [72]u8 = @splat(' ');
    pvd[0] = 1;
    @memcpy(pvd[1..6], "CD001");
    @memcpy(pvd[40..46], "cidata");
    try testing.expect(isCidata(&pvd));
    @memcpy(pvd[40..46], "CIDATA");
    try testing.expect(isCidata(&pvd));
    // Lima's seed, and macOS's hdiutil's, pad with NULs.
    @memset(pvd[46..72], 0);
    try testing.expect(isCidata(&pvd));
    @memset(pvd[46..72], ' ');
    // Another label, a label that only starts so, or no ISO9660 at all.
    @memcpy(pvd[40..46], "config");
    try testing.expect(!isCidata(&pvd));
    @memcpy(pvd[40..47], "cidata2");
    try testing.expect(!isCidata(&pvd));
    @memcpy(pvd[40..47], "cidata ");
    pvd[0] = 2; // a supplementary descriptor, not the primary
    try testing.expect(!isCidata(&pvd));
    pvd[0] = 1;
    @memcpy(pvd[1..6], "BEA01");
    try testing.expect(!isCidata(&pvd));
}
