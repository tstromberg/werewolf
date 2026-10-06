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
//! what the image carries (a DHCP client, mke2fs, cryptsetup) instead.
//!
//! Everything it reads comes from two places, in this order:
//!
//!     kernel command line   werewolf.ip=CIDR werewolf.gw=ADDR werewolf.dns=ADDR
//!                             (without werewolf.ip, the address is DHCP's)
//!                           werewolf.mac=ADDR (which NIC, when there are several)
//!                           werewolf.data=DEV (the disk /data may format, once)
//!                           (werewolf.debug=1, a root shell on the console where
//!                             the form has one, is the console service's)
//!                           and, on a machine with slots:
//!                           werewolf.victim=UUID:DIR (the filesystem holding the
//!                             slots, config.tar and data/)
//!                           werewolf.grubenv=UUID:PATH (GRUB's environment block,
//!                             which the commit service writes)
//!     config                a tar written raw to any block device, or config.tar
//!                           in the victim's directory, extracted to /run/config
//!                           for the services to read (hostname and
//!                           authorized_keys are applied here); or a NoCloud
//!                           `cidata` volume, from which only the first user and
//!                           its ssh keys are taken, which is what Lima provides;
//!                           or, failing both, the cloud's metadata server.
//!
//! It runs no shell. What it cannot do itself it asks of werewolf's programs
//! (mount, modules, net, dhcp, cloud, fence) and of the filesystem tools the
//! form carries (blkid, mke2fs, e2fsck, cryptsetup), each by its full path.
//! A step that fails is said on the console and the boot goes on, as far as
//! it can; only failing to start fence ends it, which panics the kernel and
//! sends the machine back to its last good slot.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Dir = Io.Dir;
const Allocator = std.mem.Allocator;
const linux = std.os.linux;

const mount_bin = "/usr/lib/werewolf/mount";
const path_env = "/usr/sbin:/usr/bin:/sbin:/bin";
const label = "werewolf-data";
const max_config_file = 1 << 20;

pub fn main(init: std.process.Init) !void {
    var m: Machine = .{
        .io = init.io,
        .gpa = init.arena.allocator(),
        .env = try init.environ_map.clone(init.arena.allocator()),
    };
    try m.env.put("PATH", path_env);

    // Nothing here may wait on a person. A tool that prompts (mke2fs does,
    // over an old signature) reads end of file instead of stalling the boot.
    const null_fd = linux.open("/dev/null", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(null_fd) == .SUCCESS) _ = linux.dup2(@intCast(null_fd), 0);

    m.filesystems();
    m.seed();
    m.cmd = parseCmdline(m.read("/proc/cmdline"));
    m.kernel();
    m.network();
    m.victim();
    m.config();
    m.data();

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
    seal() catch |err| {
        say("not sealed: {s}; not handing over", .{@errorName(err)});
        std.process.exit(1);
    };
    say("up in {s}s, handing over to runit", .{firstWord(m.read("/proc/uptime"))});
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
    conf_dev: []const u8 = "",
    nocloud_user: []const u8 = "",

    // --- filesystems ---------------------------------------------------------

    /// Every mount is werewolf's own (mount/mount.zig): nosuid and noexec
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
        m.mount(&.{ "-t", "devpts", "-o", "nosuid,noexec", "devpts", "/dev/pts" });
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
    /// closes for the life of the machine (modules/modules.zig); stage0 has
    /// done both, and the loader says so. Then the settings.
    fn kernel(m: *Machine) void {
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

        if (!m.run(&.{"/usr/lib/werewolf/modules"})) say("not every module loaded; see above", .{});

        var all = true;
        for (sysctls) |kv| {
            if (!writeFile(m.fmtZ("/proc/sys/{s}", .{kv[0]}), kv[1])) all = false;
        }
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
        // disk/build's say 10), or, given none, in 10: the kernel's own
        // default is to hang, and an oops now panics.
        if (std.mem.eql(u8, trim(m.read("/proc/sys/kernel/panic")), "0") and
            !writeFile(
                "/proc/sys/kernel/panic",
                "10",
            )) say("kernel.panic not set; a panic will hang", .{});
    }

    // --- the network ---------------------------------------------------------

    /// One address: the command line's, or else, in forms built on dhcp, the
    /// network's DHCP server's. A static address is for machines whose
    /// provider gives none by DHCP, or which bite took over and so keep the
    /// victim's; werewolf's net (net/net.zig) applies it. DHCP is werewolf's
    /// own client (dhcp/dhcp.zig), which applies the lease, logs it, and
    /// keeps the resolvers in its own directory; the dhcp service renews it.
    fn network(m: *Machine) void {
        _ = m.run(&.{ "/usr/lib/werewolf/net", "lo" });
        const nic = m.pickNic();
        m.routerAdvertisements(nic);
        const c = m.cmd;
        if (nic.len == 0) {
            if (c.mac.len > 0)
                say("no network: no NIC with address {s}", .{c.mac})
            else
                say("no network: no NIC", .{});
        } else if (c.ip.len > 0) {
            const ok = if (c.gw.len > 0)
                m.run(&.{ "/usr/lib/werewolf/net", nic, c.ip, c.gw })
            else
                m.run(&.{ "/usr/lib/werewolf/net", nic, c.ip });
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
            say("{s} {s} via {s} dns {s}", .{ nic, c.ip, orNone(c.gw), orNone(c.dns) });
        } else if (executable("/usr/lib/werewolf/dhcp")) {
            _ = linux.unlink("/run/resolv.conf");
            _ = linux.symlink("werewolf/dhcp/resolv.conf", "/run/resolv.conf");
            if (!m.run(&.{
                "/usr/lib/werewolf/dhcp",
                "up",
                nic,
            })) say("no network: no DHCP lease for {s}; the dhcp service keeps asking", .{nic});
        } else {
            say("no network: no werewolf.ip, and this form has no DHCP client", .{});
        }
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
        const uuid = v[0..colon];
        mkdir("/victim", 0o755);
        const dev = m.blkid(&.{ "-l", "-o", "device", "-t", m.fmt("UUID={s}", .{uuid}) });
        const mounted = m.isMounted("/victim") or
            (dev.len > 0 and m.run(&.{ mount_bin, "-o", "nosuid,nodev,noexec", dev, "/victim" }));
        if (!mounted) return say("victim's filesystem {s} not found", .{uuid});
        m.victim_dir = m.fmt("/victim{s}", .{v[colon + 1 ..]});
        say("victim's filesystem {s} on /victim, werewolf in {s}", .{ dev, m.victim_dir });
    }

    // --- the config ----------------------------------------------------------

    /// Probe every block device once. A ustar magic at byte 257 is our config
    /// tar; an ISO 9660 volume with user-data is NoCloud. Where none is found
    /// and the form has werewolf's cloud program, the config comes from the
    /// cloud's metadata server, checked and rewritten by that program before
    /// it is extracted here (docs/cloud.md).
    fn config(m: *Machine) void {
        var found = false;
        if (m.victim_dir.len > 0) {
            const tar = m.fmt("{s}/config.tar", .{m.victim_dir});
            if (exists(m.z(tar))) {
                say("config tar in {s}", .{m.victim_dir});
                m.extract(tar);
                found = true;
            }
        }
        for (m.list("/sys/class/block")) |name| {
            const dev = m.fmtZ("/dev/{s}", .{name});
            if (!isBlockDevice(dev)) continue;
            if (hasUstar(dev)) {
                say("config tar on {s}", .{dev});
                m.extract(dev);
                m.conf_dev = dev;
                found = true;
            } else if (m.runQuiet(&.{ mount_bin, "-t", "iso9660", "-o", "ro", dev, "/mnt" })) {
                if (exists("/mnt/user-data")) {
                    say("NoCloud user-data on {s}", .{dev});
                    found = true;
                    m.nocloud();
                }
                _ = linux.umount2("/mnt", 0);
            }
        }
        if (!found and executable("/usr/lib/werewolf/cloud") and
            m.run(&.{"/usr/lib/werewolf/cloud"}) and
            exists("/run/werewolf/cloud/config.tar"))
        {
            say("config tar from the cloud's metadata server", .{});
            m.extract("/run/werewolf/cloud/config.tar");
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

    /// user's ssh keys, where sshd looks (AuthorizedKeysFile).
    fn keys(m: *Machine, user: []const u8, text: []const u8) void {
        const path = m.fmtZ("/run/werewolf/keys/{s}", .{user});
        m.write(path, text, 0o600);
        const ids = lookupIds(m.read("/run/werewolf/passwd"), user) orelse return;
        _ = linux.fchownat(linux.AT.FDCWD, path, ids.uid, ids.gid, 0);
    }

    /// A config tar into /run/config, strictly: regular files and
    /// directories only, each name relative and plain, no file over 1 MiB.
    /// Files are 0600 and directories 0700, root's: the services that read
    /// the config run as root, and nothing else needs it.
    fn extract(m: *Machine, path: []const u8) void {
        var f = Dir.cwd().openFile(
            m.io,
            path,
            .{},
        ) catch |err| return say("config: {s}: {s}", .{ path, @errorName(err) });
        defer f.close(m.io);
        var rbuf: [8192]u8 = undefined;
        var r = f.readerStreaming(m.io, &rbuf);
        var name_buf: [Dir.max_path_bytes]u8 = undefined;
        var link_buf: [Dir.max_path_bytes]u8 = undefined;
        var it: std.tar.Iterator = .init(
            &r.interface,
            .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf },
        );
        while (it.next() catch |err| return say(
            "config: {s}: {s}",
            .{ path, @errorName(err) },
        )) |e| {
            const name = safeName(e.name) orelse {
                say("config: {s} refused: not a plain relative name", .{e.name});
                continue;
            };
            if (name.len == 0) continue;
            const dest = m.fmtZ("/run/config/{s}", .{name});
            switch (e.kind) {
                .directory => m.mkdirAll(dest),
                .sym_link => say("config: {s} refused: a link", .{name}),
                .file => {
                    if (e.size > max_config_file) {
                        say("config: {s} refused: over 1 MiB", .{name});
                        continue;
                    }
                    if (std.fs.path.dirname(dest)) |parent| m.mkdirAll(m.z(parent));
                    var out = Dir.cwd().createFile(
                        m.io,
                        dest,
                        .{ .permissions = .fromMode(0o600) },
                    ) catch |err| {
                        say("config: {s}: {s}", .{ name, @errorName(err) });
                        continue;
                    };
                    defer out.close(m.io);
                    var wbuf: [8192]u8 = undefined;
                    var w = out.writer(m.io, &wbuf);
                    it.streamRemaining(
                        e,
                        &w.interface,
                    ) catch |err| return say("config: {s}: {s}", .{ name, @errorName(err) });
                    w.interface.flush() catch {};
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
    /// The form's packages decide what /data is, so init never asks which
    /// form it is in:
    ///
    ///     no mke2fs        tmpfs, capped at a quarter of RAM: the form keeps nothing
    ///     mke2fs           ext4 on the device labelled werewolf-data
    ///     + cryptsetup     the same inside LUKS2, keyed by data.key from the config
    ///
    /// The disk is found by its label, so its device name may differ from
    /// boot to boot.
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
            // writable. What must write there (commit; the updater) mounts
            // it again, apart.
            if (m.run(&.{
                mount_bin,
                "-o",
                "remount,bind,ro,nosuid,nodev,noexec",
                "/victim",
            })) say("/victim is read-only", .{});
        } else if (m.which("mke2fs") == null) {
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
        const crypt = m.which("cryptsetup");
        const want: []const u8 = if (crypt != null) "crypto_LUKS" else "ext4";
        var fresh = false;

        var src = m.blkid(&.{ "-l", "-o", "device", "-t", "LABEL=" ++ label });
        if (src.len > 0) {
            const have = m.blkid(&.{ "-p", "-o", "value", "-s", "TYPE", src });
            if (!std.mem.eql(u8, have, want)) {
                why.* = m.fmt("{s} is {s}, this form wants {s}", .{ src, have, want });
                return null;
            }
        } else {
            const d = m.cmd.data;
            if (d.len == 0) {
                why.* = "no " ++ label ++ " disk, and werewolf.data names none";
                return null;
            }
            src = m.fmt(
                "/dev/{s}",
                .{if (std.mem.startsWith(u8, d, "/dev/")) d["/dev/".len..] else d},
            );
            if (!isBlockDevice(m.z(src))) {
                why.* = m.fmt("werewolf.data: no device {s}", .{src});
                return null;
            }
            if (std.mem.eql(u8, src, m.conf_dev)) {
                why.* = m.fmt("werewolf.data: {s} holds the config", .{src});
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
            const key = "/run/config/data.key";
            if (m.read(key).len == 0) {
                why.* = "no data.key in the config";
                return null;
            }
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
        // reason to stop.
        if (fresh) {
            say("formatting {s}", .{fs});
            const mke2fs = m.which("mke2fs").?;
            const ok = if (crypt != null)
                m.run(&.{ mke2fs, "-q", "-F", "-t", "ext4", "-m", "0", fs })
            else
                m.run(&.{ mke2fs, "-q", "-F", "-t", "ext4", "-m", "0", "-L", label, fs });
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
            .exited => |code| if (code == 0) trim(firstLine(res.stdout)) else "",
            else => "",
        };
    }

    // --- files ---------------------------------------------------------------

    fn isMounted(m: *Machine, point: []const u8) bool {
        var it = std.mem.tokenizeScalar(u8, m.read("/proc/self/mounts"), '\n');
        while (it.next()) |line| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            _ = f.next() orelse continue;
            if (std.mem.eql(u8, f.next() orelse continue, point)) return true;
        }
        return false;
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

/// System calls no program here makes once init hands over, refused for
/// every process the machine will run (design/lockdown.md, the seal), each
/// where the architecture has it:
///
///   bpf, perf_event_open           eBPF and kernel tracing, which rootkits
///                                  are made of
///   init_module .. delete_module   modules: the loader closed already
///   kexec_load, kexec_file_load    another kernel: lockdown refuses already
///   io_uring_*                     makes kernel.io_uring_disabled permanent
///   userfaultfd                    the usual way to win a kernel race
///   open_by_handle_at, name_..     walking past mounts by inode handle
///   add_key, keyctl, request_key   the kernel keyring; cryptsetup is done
///                                  with it before init hands over
///   process_vm_readv, _writev      another process's memory: Yama refuses
///   modify_ldt, iopl, ioperm       16-bit code and I/O ports
///   acct .. vhangup                unused here; old, rarely audited code
///
/// syslog stays: busybox's dmesg reads the kernel's log with it.
const denied_names = [_][]const u8{
    "bpf",               "perf_event_open",   "init_module",     "finit_module",
    "delete_module",     "kexec_load",        "kexec_file_load", "io_uring_setup",
    "io_uring_enter",    "io_uring_register", "userfaultfd",     "open_by_handle_at",
    "name_to_handle_at", "add_key",           "keyctl",          "request_key",
    "process_vm_readv",  "process_vm_writev", "modify_ldt",      "iopl",
    "ioperm",            "acct",              "swapon",          "swapoff",
    "quotactl",          "lookup_dcookie",    "uselib",          "vhangup",
};

const denied: []const linux.SYS = blk: {
    var list: []const linux.SYS = &.{};
    for (denied_names) |name| {
        if (@hasField(linux.SYS, name)) list = list ++ [_]linux.SYS{@field(linux.SYS, name)};
    }
    break :blk list;
};

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

/// The architecture every system call must come in as. Any other, which on
/// aarch64 is a 32-bit (AArch32) program's, kills the process: werewolf ships
/// no 32-bit code, and the kernel has no switch to turn those calls off.
const native_arch: u32 = switch (builtin.cpu.arch) {
    .aarch64 => 0xc00000b7, // AUDIT_ARCH_AARCH64
    .x86_64 => 0xc000003e, // AUDIT_ARCH_X86_64
    else => unreachable,
};

const Filter = extern struct { code: u16, jt: u8, jf: u8, k: u32 };
const LD_W_ABS = 0x20;
const JEQ_K = 0x15;
const JGE_K = 0x35;
const RET_K = 0x06;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_ERRNO: u32 = 0x00050000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

/// Load the architecture; kill another; load the number; each denied number
/// jumps to the ENOSYS at the end, as if the kernel had no such call; the
/// rest are allowed. It reads numbers, never arguments, so the kernel
/// caches every allowed call as allowed and runs no filter for it, and a
/// longer table costs nothing more. What any filter costs is the kernel's
/// slower way into every system call, about 25 ns a call (design/lockdown.md,
/// *What the seal costs*): werewolf pays that, by choice.
///
/// On x86_64 a number with bit 30 set is an x32 call, under x86_64's own
/// architecture: it would pass every comparison below as another number,
/// so it kills the process too. Alpine's kernel has no x32 ABI; the check
/// keeps one that does from opening the table.
const seal_filter = blk: {
    const n = denied.len;
    const x32 = builtin.cpu.arch == .x86_64;
    const at = if (x32) 6 else 4; // the first comparison
    var f: [at + 2 + n]Filter = undefined;
    f[0] = .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 4 }; // seccomp_data.arch
    f[1] = .{ .code = JEQ_K, .jt = 1, .jf = 0, .k = native_arch };
    f[2] = .{ .code = RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
    f[3] = .{ .code = LD_W_ABS, .jt = 0, .jf = 0, .k = 0 }; // seccomp_data.nr
    if (x32) {
        f[4] = .{ .code = JGE_K, .jt = 0, .jf = 1, .k = 0x40000000 }; // __X32_SYSCALL_BIT
        f[5] = .{ .code = RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
    }
    for (denied, 0..) |sys, i| f[at + i] = .{
        .code = JEQ_K,
        .jt = @intCast(n - i),
        .jf = 0,
        .k = @intCast(@backingInt(sys)),
    };
    f[at + n] = .{ .code = RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_ALLOW };
    f[at + 1 + n] = .{
        .code = RET_K,
        .jt = 0,
        .jf = 0,
        .k = SECCOMP_RET_ERRNO | @backingInt(linux.E.NOSYS),
    };
    break :blk f;
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

/// Install the seal on PID 1, which every process inherits and none, root
/// included, can remove until the machine reboots: the helpers' bounding
/// set, PID 1's, then the filter. PID 1 holds CAP_SYS_ADMIN, so it needs no
/// no_new_privs, which would bind every program after it. Any step that
/// fails is an error; a capability the kernel does not know (EINVAL) is
/// one it cannot grant.
fn seal() !void {
    var buf: [32]u8 = undefined;
    for ([_][:0]const u8{
        "/proc/sys/kernel/usermodehelper/bset",
        "/proc/sys/kernel/usermodehelper/inheritable",
    }, [_]u64{ helper_caps, 0 }) |path, set| {
        if (!writeFile(path, capWords(&buf, set))) return error.UsermodeHelperCaps;
    }
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
    const SECCOMP_SET_MODE_FILTER = 1;
    const prog = extern struct {
        len: u16,
        filter: [*]const Filter,
    }{ .len = seal_filter.len, .filter = &seal_filter };
    const rc = linux.seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog);
    if (linux.errno(rc) != .SUCCESS) {
        say("seccomp: {t}", .{linux.errno(rc)});
        return error.Seccomp;
    }
    say(
        "sealed: {d} system calls refused, {d} capabilities dropped, other architectures' calls " ++
            "fatal",
        .{ denied.len, caps },
    );
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

fn writeFile(path: [:0]const u8, data: []const u8) bool {
    const fd = linux.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return false;
    defer _ = linux.close(@intCast(fd));
    const n = linux.write(@intCast(fd), data.ptr, data.len);
    return linux.errno(n) == .SUCCESS and n == data.len;
}

fn say(comptime f: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const line = std.mem.print(&buf, "werewolf: " ++ f ++ "\n", args) catch return;
    _ = linux.write(1, line.ptr, line.len);
}

// --- tests -------------------------------------------------------------------

const testing = std.testing;

/// What seal_filter returns for a call: the filter run as the kernel runs
/// it, for the few instructions it uses.
fn sealAction(arch: u32, nr: u32) u32 {
    var a: u32 = 0;
    var pc: usize = 0;
    while (true) {
        const i = seal_filter[pc];
        switch (i.code) {
            LD_W_ABS => a = if (i.k == 4) arch else nr,
            JEQ_K => pc += if (a == i.k) i.jt else i.jf,
            JGE_K => pc += if (a >= i.k) i.jt else i.jf,
            RET_K => return i.k,
            else => unreachable,
        }
        pc += 1;
    }
}

test seal_filter {
    const enosys = SECCOMP_RET_ERRNO | @backingInt(linux.E.NOSYS);
    for (denied) |sys| try testing.expectEqual(
        enosys,
        sealAction(native_arch, @intCast(@backingInt(sys))),
    );
    for ([_]linux.SYS{
        .read,
        .write,
        .openat,
        .mmap,
        .futex,
        .getpid,
    }) |sys| try testing.expectEqual(
        SECCOMP_RET_ALLOW,
        sealAction(native_arch, @intCast(@backingInt(sys))),
    );
    try testing.expectEqual(SECCOMP_RET_KILL_PROCESS, sealAction(0x40000028, 0)); // AUDIT_ARCH_ARM
    try testing.expectEqual(SECCOMP_RET_KILL_PROCESS, sealAction(0x40000003, 0)); // AUDIT_ARCH_I386
    // x32: a denied number, or any, with bit 30 set.
    if (builtin.cpu.arch == .x86_64) for ([_]u32{ 0x40000000, 0x40000000 | 154, 0xffffffff }) |nr| {
        try testing.expectEqual(SECCOMP_RET_KILL_PROCESS, sealAction(native_arch, nr));
    };
    try testing.expectEqual(SECCOMP_RET_ALLOW, sealAction(native_arch, 0x3fffffff));
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
