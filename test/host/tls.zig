//! tls serves TLS 1.3 to host-side tests, never on a machine. It speaks one
//! suite (TLS_AES_128_GCM_SHA256), one group (x25519) and one signature
//! (ecdsa_secp256r1_sha256): no resumption, no HelloRetryRequest and no
//! client certificates. Authority mints the certificates a test serves and
//! its clients trust. See test/host/README.md.

const std = @import("std");
const tls = std.crypto.tls;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
const X25519 = std.crypto.dh.X25519;
pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Identity is what a server presents: its key and its chain, leaf first.
pub const Identity = struct {
    key: Ecdsa.KeyPair,
    chain: []const []const u8,
};

/// Authority is a test certificate authority. Its clients trust what pem writes.
pub const Authority = struct {
    name: []const u8,
    key: Ecdsa.KeyPair,
    der: []const u8,

    pub fn init(io: Io, gpa: Allocator, name: []const u8) !Authority {
        const key = Ecdsa.KeyPair.generate(io);
        return .{ .name = name, .key = key, .der = try certificate(io, gpa, .{
            .subject = name,
            .key = key.public_key,
            .issuer = name,
            .signer = key,
        }) };
    }

    /// issue certifies a server for names, DNS names or IP literals.
    pub fn issue(a: Authority, io: Io, gpa: Allocator, names: []const []const u8) !Identity {
        if (names.len == 0) return error.NoNames;
        const key = Ecdsa.KeyPair.generate(io);
        const leaf = try certificate(io, gpa, .{
            .subject = names[0],
            .key = key.public_key,
            .issuer = a.name,
            .signer = a.key,
            .names = names,
        });
        return .{ .key = key, .chain = try gpa.dupe([]const u8, &.{ leaf, a.der }) };
    }

    pub fn pem(a: Authority, gpa: Allocator) ![]u8 {
        const Base64 = std.base64.standard.Encoder;
        const text = try gpa.alloc(u8, Base64.calcSize(a.der.len));
        _ = Base64.encode(text, a.der);
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(gpa, "-----BEGIN CERTIFICATE-----\n");
        var i: usize = 0;
        while (i < text.len) : (i += 64) {
            try out.appendSlice(gpa, text[i..@min(i + 64, text.len)]);
            try out.append(gpa, '\n');
        }
        try out.appendSlice(gpa, "-----END CERTIFICATE-----\n");
        return out.toOwnedSlice(gpa);
    }
};

const oid = struct {
    const ecdsa_sha256 = "\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";
    const ec_public_key = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
    const prime256v1 = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
    const common_name = "\x06\x03\x55\x04\x03";
    const subject_key_id = "\x06\x03\x55\x1d\x0e";
    const key_usage = "\x06\x03\x55\x1d\x0f";
    const subject_alt_name = "\x06\x03\x55\x1d\x11";
    const basic_constraints = "\x06\x03\x55\x1d\x13";
    const authority_key_id = "\x06\x03\x55\x1d\x23";
    const ext_key_usage = "\x06\x03\x55\x1d\x25";
    const server_auth = "\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01";
};

const Template = struct {
    subject: []const u8,
    key: Ecdsa.PublicKey,
    issuer: []const u8,
    signer: Ecdsa.KeyPair,
    /// names makes a server's certificate; none makes an authority's.
    names: []const []const u8 = &.{},
};

/// certificate is a DER X.509 v3 certificate, valid from an hour ago for two days.
fn certificate(io: Io, gpa: Allocator, t: Template) ![]const u8 {
    var serial: [16]u8 = undefined;
    io.random(&serial);
    serial[0] = (serial[0] & 0x3f) | 0x40;
    const now = @divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
    const algorithm = try der(gpa, 0x30, &.{oid.ecdsa_sha256});
    var extensions: std.ArrayList([]const u8) = .empty;
    if (t.names.len == 0) {
        try extensions.append(
            gpa,
            try extension(gpa, oid.basic_constraints, true, "\x30\x03\x01\x01\xff"),
        );
        // keyCertSign and cRLSign.
        try extensions.append(gpa, try extension(gpa, oid.key_usage, true, "\x03\x02\x01\x06"));
    } else {
        // digitalSignature.
        try extensions.append(gpa, try extension(gpa, oid.key_usage, true, "\x03\x02\x07\x80"));
        try extensions.append(
            gpa,
            try extension(gpa, oid.ext_key_usage, false, "\x30\x0a" ++ oid.server_auth),
        );
        var names: std.ArrayList([]const u8) = .empty;
        for (t.names) |name| try names.append(gpa, if (Io.net.IpAddress.parse(name, 0)) |ip|
            switch (ip) {
                .ip4 => |a| try der(gpa, 0x87, &.{&a.bytes}),
                .ip6 => |a| try der(gpa, 0x87, &.{&a.bytes}),
            }
        else |_|
            try der(gpa, 0x82, &.{name}));
        try extensions.append(
            gpa,
            try extension(gpa, oid.subject_alt_name, false, try der(gpa, 0x30, names.items)),
        );
    }
    try extensions.append(
        gpa,
        try extension(gpa, oid.subject_key_id, false, try der(gpa, 0x04, &.{&keyId(t.key)})),
    );
    const authority = try der(gpa, 0x30, &.{try der(gpa, 0x80, &.{&keyId(t.signer.public_key)})});
    try extensions.append(gpa, try extension(gpa, oid.authority_key_id, false, authority));
    const point = t.key.toUncompressedSec1();
    const tbs = try der(gpa, 0x30, &.{
        "\xa0\x03\x02\x01\x02",
        try der(gpa, 0x02, &.{&serial}),
        algorithm,
        try distinguished(gpa, t.issuer),
        try der(gpa, 0x30, &.{ try utcTime(gpa, now - 3600), try utcTime(gpa, now + 2 * 86400) }),
        try distinguished(gpa, t.subject),
        try der(
            gpa,
            0x30,
            &.{
                try der(gpa, 0x30, &.{ oid.ec_public_key, oid.prime256v1 }),
                try der(gpa, 0x03, &.{ "\x00", &point }),
            },
        ),
        try der(gpa, 0xa3, &.{try der(gpa, 0x30, extensions.items)}),
    });
    var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const signature = (try t.signer.sign(tbs, null)).toDer(&buf);
    return der(gpa, 0x30, &.{ tbs, algorithm, try der(gpa, 0x03, &.{ "\x00", signature }) });
}

/// der is one DER element: tag, length and the parts as its contents.
fn der(gpa: Allocator, tag: u8, parts: []const []const u8) ![]const u8 {
    var len: usize = 0;
    for (parts) |part| len += part.len;
    if (len > 0xffff) return error.TooLong;
    var out: std.ArrayList(u8) = try .initCapacity(gpa, 4 + len);
    out.appendAssumeCapacity(tag);
    if (len >= 0x100) {
        out.appendSliceAssumeCapacity(&.{ 0x82, @intCast(len >> 8), @truncate(len) });
    } else if (len >= 0x80) {
        out.appendSliceAssumeCapacity(&.{ 0x81, @intCast(len) });
    } else out.appendAssumeCapacity(@intCast(len));
    for (parts) |part| out.appendSliceAssumeCapacity(part);
    return out.items;
}

fn extension(gpa: Allocator, id: []const u8, critical: bool, value: []const u8) ![]const u8 {
    return der(
        gpa,
        0x30,
        &.{ id, if (critical) "\x01\x01\xff" else "", try der(gpa, 0x04, &.{value}) },
    );
}

fn distinguished(gpa: Allocator, common_name: []const u8) ![]const u8 {
    const attribute = try der(
        gpa,
        0x30,
        &.{ oid.common_name, try der(gpa, 0x0c, &.{common_name}) },
    );
    return der(gpa, 0x30, &.{try der(gpa, 0x31, &.{attribute})});
}

fn utcTime(gpa: Allocator, seconds: i96) ![]const u8 {
    const at: std.time.epoch.EpochSeconds = .{ .secs = @intCast(seconds) };
    const year = at.getEpochDay().calculateYearDay();
    const month = year.calculateMonthDay();
    const day = at.getDaySeconds();
    if (year.year < 1950 or year.year > 2049) return error.UtcTimeRange;
    return der(gpa, 0x17, &.{try gpa.print("{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
        year.year % 100,       month.month.numeric(),    month.day_index + 1,
        day.getHoursIntoDay(), day.getMinutesIntoHour(), day.getSecondsIntoMinute(),
    })});
}

fn keyId(key: Ecdsa.PublicKey) [20]u8 {
    var digest: [32]u8 = undefined;
    Sha256.hash(&key.toUncompressedSec1(), &digest, .{});
    return digest[0..20].*;
}

const max_fragment = tls.max_ciphertext_inner_record_len;
/// input_buffer_len and clear_buffer_len are the least buffers accept takes:
/// a whole record, and its cleartext.
pub const input_buffer_len = tls.max_ciphertext_record_len;
pub const clear_buffer_len = tls.max_ciphertext_len;
const tag_length = Aead.tag_length;

/// Connection is one accepted TLS 1.3 session. reader and writer carry its
/// cleartext; writer.flush sends what is written. It must not move once
/// accept has begun: reader and writer find it by their own addresses.
pub const Connection = struct {
    input: *Io.Reader,
    output: *Io.Writer,
    reader: Io.Reader,
    writer: Io.Writer,
    read: Secret,
    write: Secret,
    /// alpn is the application protocol agreed, if any.
    alpn: ?[]const u8 = null,
    /// closed is set by the client's close_notify.
    closed: bool = false,
    /// failure is why the last read failed.
    failure: ?anyerror = null,

    const Secret = struct {
        secret: [32]u8,
        key: [Aead.key_length]u8,
        iv: [Aead.nonce_length]u8,
        seq: u64 = 0,

        fn init(secret: [32]u8) Secret {
            return .{
                .secret = secret,
                .key = tls.hkdfExpandLabel(Hkdf, secret, "key", "", Aead.key_length),
                .iv = tls.hkdfExpandLabel(Hkdf, secret, "iv", "", Aead.nonce_length),
            };
        }

        fn nonce(s: *Secret) ![Aead.nonce_length]u8 {
            var n = s.iv;
            const seq = mem.toBytes(mem.nativeToBig(u64, s.seq));
            for (n[n.len - 8 ..], seq) |*b, q| b.* ^= q;
            s.seq = std.math.add(u64, s.seq, 1) catch return error.TlsSequenceOverflow;
            return n;
        }
    };

    /// accept runs the server's side of a handshake on c, with buffers of at
    /// least input_buffer_len and clear_buffer_len.
    pub fn accept(
        c: *Connection,
        io: Io,
        input: *Io.Reader,
        output: *Io.Writer,
        identity: *const Identity,
        read_buffer: []u8,
        write_buffer: []u8,
    ) !void {
        if (input.buffer.len < input_buffer_len or read_buffer.len < clear_buffer_len)
            return error.TlsBufferTooSmall;
        c.* = .{
            .input = input,
            .output = output,
            .reader = .{
                .buffer = read_buffer,
                .vtable = &.{ .stream = streamRecord, .readVec = readVec },
                .seek = 0,
                .end = 0,
            },
            .writer = .{ .buffer = write_buffer, .vtable = &.{ .drain = drain, .flush = flush } },
            .read = undefined,
            .write = undefined,
        };
        handshake(c, io, identity) catch |err| {
            // A refusal is the client's to read; an unreadable client gets none.
            if (alertFor(err)) |description| {
                output.writeAll(&.{ 21, 3, 3, 0, 2, 2, @backingInt(description) }) catch {};
                output.flush() catch {};
            }
            return err;
        };
    }

    /// end sends close_notify after what is written.
    pub fn end(c: *Connection) Io.Writer.Error!void {
        try c.writer.flush();
        try c.seal(.alert, &.{ 1, @backingInt(tls.Alert.Description.close_notify) });
        try c.output.flush();
    }

    fn seal(c: *Connection, kind: tls.ContentType, bytes: []const u8) Io.Writer.Error!void {
        var i: usize = 0;
        while (true) {
            const n = @min(bytes.len - i, max_fragment);
            var clear: [max_fragment + 1]u8 = undefined;
            @memcpy(clear[0..n], bytes[i..][0..n]);
            clear[n] = @backingInt(kind);
            const len: u16 = @intCast(n + 1 + tag_length);
            const header = [5]u8{
                @backingInt(tls.ContentType.application_data),
                3,
                3,
                @intCast(len >> 8),
                @truncate(len),
            };
            var sealed: [max_fragment + 1]u8 = undefined;
            var tag: [tag_length]u8 = undefined;
            const nonce = c.write.nonce() catch return error.WriteFailed;
            Aead.encrypt(sealed[0 .. n + 1], &tag, clear[0 .. n + 1], &header, nonce, c.write.key);
            try c.output.writeAll(&header);
            try c.output.writeAll(sealed[0 .. n + 1]);
            try c.output.writeAll(&tag);
            i += n;
            if (i == bytes.len) return;
        }
    }

    /// open decrypts the next record into dest: its content and inner type.
    fn open(c: *Connection, dest: []u8) !struct { tls.ContentType, []const u8 } {
        const header = (try c.input.takeArray(5)).*;
        if (header[0] != @backingInt(
            tls.ContentType.application_data,
        )) return error.TlsUnexpectedMessage;
        const len = mem.readInt(u16, header[3..5], .big);
        if (len > tls.max_ciphertext_len or len < tag_length + 1) return error.TlsRecordOverflow;
        const body = try c.input.take(len);
        const sealed = body[0 .. len - tag_length];
        if (sealed.len > dest.len) return error.TlsRecordOverflow;
        Aead.decrypt(
            dest[0..sealed.len],
            sealed,
            body[len - tag_length ..][0..tag_length].*,
            &header,
            try c.read.nonce(),
            c.read.key,
        ) catch
            return error.TlsBadRecordMac;
        const clear = mem.trimEnd(u8, dest[0..sealed.len], "\x00");
        if (clear.len == 0) return error.TlsDecodeError;
        return .{ @fromBackingInt(clear[clear.len - 1]), clear[0 .. clear.len - 1] };
    }
};

fn alertFor(err: anyerror) ?tls.Alert.Description {
    return switch (err) {
        error.TlsProtocolVersion => .protocol_version,
        error.TlsHandshakeFailure => .handshake_failure,
        error.TlsDecodeError => .decode_error,
        error.TlsDecryptError => .decrypt_error,
        error.TlsBadRecordMac => .bad_record_mac,
        error.TlsUnexpectedMessage => .unexpected_message,
        error.TlsIllegalParameter => .illegal_parameter,
        error.TlsRecordOverflow => .record_overflow,
        else => null,
    };
}

/// Hello is what the server needs of a ClientHello.
const Hello = struct {
    session: []const u8,
    share: [32]u8,
    http1: bool,
};

/// Cursor reads a handshake body, refusing what overruns it.
const Cursor = struct {
    data: []const u8,
    i: usize = 0,

    fn int(c: *Cursor, comptime T: type) !T {
        const bytes = try c.take(@sizeOf(T));
        return mem.readInt(T, bytes[0..@sizeOf(T)], .big);
    }

    fn take(c: *Cursor, n: usize) ![]const u8 {
        if (c.data.len - c.i < n) return error.TlsDecodeError;
        defer c.i += n;
        return c.data[c.i..][0..n];
    }

    fn vector(c: *Cursor, comptime Len: type) !Cursor {
        return .{ .data = try c.take(try c.int(Len)) };
    }

    fn done(c: Cursor) bool {
        return c.i == c.data.len;
    }

    /// has reports whether a list of T holds want, reading all of it.
    fn has(c: *Cursor, comptime T: type, want: T) !bool {
        var found = false;
        while (!c.done()) {
            if (try c.int(T) == want) found = true;
        }
        return found;
    }
};

fn parseHello(body: []const u8) !Hello {
    var c: Cursor = .{ .data = body };
    _ = try c.int(u16);
    _ = try c.take(32);
    const session = (try c.vector(u8)).data;
    if (session.len > 32) return error.TlsDecodeError;
    var suites = try c.vector(u16);
    const suite = try suites.has(u16, @backingInt(tls.CipherSuite.AES_128_GCM_SHA256));
    _ = try c.vector(u8);
    var extensions = try c.vector(u16);
    if (!c.done()) return error.TlsDecodeError;
    var tls13 = false;
    var signature = false;
    var share: ?[32]u8 = null;
    var http1 = false;
    while (!extensions.done()) {
        const kind = try extensions.int(u16);
        var data = try extensions.vector(u16);
        switch (kind) {
            @backingInt(tls.ExtensionType.supported_versions) => {
                var versions = try data.vector(u8);
                tls13 = try versions.has(u16, @backingInt(tls.ProtocolVersion.tls_1_3));
            },
            @backingInt(tls.ExtensionType.signature_algorithms) => {
                var schemes = try data.vector(u16);
                signature = try schemes.has(
                    u16,
                    @backingInt(tls.SignatureScheme.ecdsa_secp256r1_sha256),
                );
            },
            @backingInt(tls.ExtensionType.key_share) => {
                var shares = try data.vector(u16);
                while (!shares.done()) {
                    const group = try shares.int(u16);
                    const key = (try shares.vector(u16)).data;
                    if (group == @backingInt(tls.NamedGroup.x25519) and
                        key.len == 32) share = key[0..32].*;
                }
            },
            @backingInt(tls.ExtensionType.application_layer_protocol_negotiation) => {
                var protocols = try data.vector(u16);
                while (!protocols.done()) {
                    if (mem.eql(u8, (try protocols.vector(u8)).data, "http/1.1")) http1 = true;
                }
            },
            else => {},
        }
    }
    if (!tls13) return error.TlsProtocolVersion;
    if (!suite or !signature) return error.TlsHandshakeFailure;
    return .{
        .session = session,
        .share = share orelse return error.TlsHandshakeFailure,
        .http1 = http1,
    };
}

/// Transcript keeps the handshake's hash and the message bytes it frames.
const Transcript = struct {
    hash: Sha256 = .init(.{}),
    buf: [8192]u8 = undefined,

    /// message frames body as a handshake message and adds it to the hash.
    fn message(t: *Transcript, kind: tls.HandshakeType, parts: []const []const u8) ![]const u8 {
        var len: usize = 0;
        for (parts) |part| len += part.len;
        if (4 + len > t.buf.len) return error.TlsRecordOverflow;
        t.buf[0] = @backingInt(kind);
        mem.writeInt(u24, t.buf[1..4], @intCast(len), .big);
        var i: usize = 4;
        for (parts) |part| {
            @memcpy(t.buf[i..][0..part.len], part);
            i += part.len;
        }
        t.hash.update(t.buf[0..i]);
        return t.buf[0..i];
    }
};

fn handshake(c: *Connection, io: Io, identity: *const Identity) !void {
    var transcript: Transcript = .{};
    var hello_buf: [max_fragment]u8 = undefined;
    const hello = try readHello(c.input, &hello_buf);
    transcript.hash.update(hello);
    const offer = try parseHello(hello[4..]);
    if (offer.http1) c.alpn = "http/1.1";

    var random: [32]u8 = undefined;
    io.random(&random);
    const share = X25519.KeyPair.generate(io);
    const shared = X25519.scalarmult(
        share.secret_key,
        offer.share,
    ) catch return error.TlsIllegalParameter;
    const server_hello = try transcript.message(.server_hello, &.{
        &int(
            u16,
            0x0303,
        ),
        &random,
        &.{
            @intCast(offer.session.len),
        },
        offer.session,
        &int(
            u16,
            @backingInt(tls.CipherSuite.AES_128_GCM_SHA256),
        ),
        &.{0},
        &int(
            u16,
            6 + 40,
        ),
        &tls.extension(.supported_versions, int(u16, 0x0304)),
        &tls.extension(
            .key_share,
            int(u16, @backingInt(tls.NamedGroup.x25519)) ++ int(u16, 32) ++ share.public_key,
        ),
    });
    try record(c.output, .handshake, server_hello);
    // For middleboxes that remember TLS 1.2 (RFC 8446, Appendix D.4).
    try c.output.writeAll(&.{ 20, 3, 3, 0, 1, 1 });

    const zeros: [32]u8 = @splat(0);
    const empty = tls.emptyHash(Sha256);
    const early = Hkdf.extract(&.{}, &zeros);
    const secret = Hkdf.extract(&tls.hkdfExpandLabel(Hkdf, early, "derived", &empty, 32), &shared);
    const hello_hash = transcript.hash.peek();
    const client_secret = tls.hkdfExpandLabel(Hkdf, secret, "c hs traffic", &hello_hash, 32);
    c.write = .init(tls.hkdfExpandLabel(Hkdf, secret, "s hs traffic", &hello_hash, 32));
    c.read = .init(client_secret);

    const alpn = tls.extension(
        .application_layer_protocol_negotiation,
        int(u16, 9) ++ [_]u8{8} ++ "http/1.1".*,
    );
    try c.seal(.handshake, try transcript.message(.encrypted_extensions, &.{
        &int(u16, if (c.alpn == null) 0 else alpn.len), if (c.alpn == null) "" else &alpn,
    }));

    var certificates: [8192]u8 = undefined;
    var list: Io.Writer = .fixed(&certificates);
    for (identity.chain) |cert| {
        try list.writeInt(u24, @intCast(cert.len), .big);
        try list.writeAll(cert);
        try list.writeInt(u16, 0, .big);
    }
    try c.seal(.handshake, try transcript.message(.certificate, &.{
        &.{0}, &int(u24, @intCast(list.end)), list.buffered(),
    }));

    const signed = @as([64]u8, @splat(0x20)) ++ "TLS 1.3, server CertificateVerify".* ++ [_]u8{0} ++
        transcript.hash.peek();
    var signature_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const signature = (try identity.key.sign(&signed, null)).toDer(&signature_buf);
    try c.seal(.handshake, try transcript.message(.certificate_verify, &.{
        &int(
            u16,
            @backingInt(tls.SignatureScheme.ecdsa_secp256r1_sha256),
        ),
        &int(u16, @intCast(signature.len)),
        signature,
    }));

    const server_finished = tls.hmac(
        Hmac,
        &transcript.hash.peek(),
        tls.hkdfExpandLabel(Hkdf, c.write.secret, "finished", "", 32),
    );
    try c.seal(.handshake, try transcript.message(.finished, &.{&server_finished}));
    try c.output.flush();

    const application_hash = transcript.hash.peek();
    const master = Hkdf.extract(&tls.hkdfExpandLabel(Hkdf, secret, "derived", &empty, 32), &zeros);
    const expected = tls.hmac(
        Hmac,
        &application_hash,
        tls.hkdfExpandLabel(Hkdf, client_secret, "finished", "", 32),
    );
    while (true) {
        const header = try c.input.peekArray(5);
        if (header[0] == @backingInt(tls.ContentType.change_cipher_spec)) {
            const ccs = try c.input.takeArray(6);
            if (!mem.eql(u8, ccs, &.{ 20, 3, 3, 0, 1, 1 })) return error.TlsUnexpectedMessage;
            continue;
        }
        var clear: [tls.max_ciphertext_len]u8 = undefined;
        const kind, const content = try c.open(&clear);
        if (kind != .handshake or content.len != 4 + 32 or
            content[0] != @backingInt(tls.HandshakeType.finished) or
            mem.readInt(u24, content[1..4], .big) != 32) return error.TlsUnexpectedMessage;
        if (!std.crypto.timing_safe.eql(
            [32]u8,
            content[4..36].*,
            expected,
        )) return error.TlsDecryptError;
        break;
    }
    c.read = .init(tls.hkdfExpandLabel(Hkdf, master, "c ap traffic", &application_hash, 32));
    c.write = .init(tls.hkdfExpandLabel(Hkdf, master, "s ap traffic", &application_hash, 32));
}

/// readHello takes a ClientHello, in plaintext records, as one message.
fn readHello(input: *Io.Reader, buf: []u8) ![]const u8 {
    var len: usize = 0;
    while (true) {
        const header = (try input.takeArray(5)).*;
        if (header[0] != @backingInt(tls.ContentType.handshake)) return error.TlsUnexpectedMessage;
        const n = mem.readInt(u16, header[3..5], .big);
        if (n == 0 or n > max_fragment or len + n > buf.len) return error.TlsRecordOverflow;
        try input.readSliceAll(buf[len..][0..n]);
        len += n;
        if (len < 4) continue;
        if (buf[0] != @backingInt(
            tls.HandshakeType.client_hello,
        )) return error.TlsUnexpectedMessage;
        const want = 4 + @as(usize, mem.readInt(u24, buf[1..4], .big));
        if (len == want) return buf[0..len];
        if (len > want or want > buf.len) return error.TlsDecodeError;
    }
}

fn record(output: *Io.Writer, kind: tls.ContentType, bytes: []const u8) !void {
    try output.writeAll(&(.{@backingInt(kind)} ++ int(u16, 0x0303) ++
        int(u16, @intCast(bytes.len))));
    try output.writeAll(bytes);
}

fn int(comptime T: type, value: T) [@divExact(@bitSizeOf(T), 8)]u8 {
    var out: [@divExact(@bitSizeOf(T), 8)]u8 = undefined;
    mem.writeInt(T, &out, value, .big);
    return out;
}

fn streamRecord(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    _ = w;
    _ = limit;
    return fill(@alignCast(@fieldParentPtr("reader", r)));
}

fn readVec(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
    _ = data;
    return fill(@alignCast(@fieldParentPtr("reader", r)));
}

/// fill decrypts one record into reader's buffer, as tls.Client does.
fn fill(c: *Connection) Io.Reader.Error!usize {
    const r = &c.reader;
    if (c.closed) return error.EndOfStream;
    if (r.buffer.len - r.end < tls.max_ciphertext_len) {
        const kept = r.buffer[r.seek..r.end];
        @memmove(r.buffer[0..kept.len], kept);
        r.seek = 0;
        r.end = kept.len;
    }
    const kind, const content = c.open(r.buffer[r.end..]) catch |err| switch (err) {
        error.EndOfStream => return error.EndOfStream,
        else => {
            c.failure = err;
            return error.ReadFailed;
        },
    };
    switch (kind) {
        .application_data => r.end += content.len,
        .alert => {
            if (content.len == 2 and
                content[1] == @backingInt(tls.Alert.Description.close_notify))
            {
                c.closed = true;
                return error.EndOfStream;
            }
            c.failure = error.TlsAlert;
            return error.ReadFailed;
        },
        .handshake => keyUpdate(c, content) catch |err| {
            c.failure = err;
            return error.ReadFailed;
        },
        else => {
            c.failure = error.TlsUnexpectedMessage;
            return error.ReadFailed;
        },
    }
    return 0;
}

/// keyUpdate takes the client's new key, and gives one back if asked.
/// Session tickets are the server's to send, so a client sends nothing else.
fn keyUpdate(c: *Connection, content: []const u8) !void {
    if (content.len != 5 or content[0] != @backingInt(tls.HandshakeType.key_update) or
        mem.readInt(u24, content[1..4], .big) != 1) return error.TlsUnexpectedMessage;
    c.read = .init(tls.hkdfExpandLabel(Hkdf, c.read.secret, "traffic upd", "", 32));
    switch (content[4]) {
        0 => {},
        1 => {
            try c.writer.flush();
            try c.seal(.handshake, &.{ @backingInt(tls.HandshakeType.key_update), 0, 0, 1, 0 });
            c.write = .init(tls.hkdfExpandLabel(Hkdf, c.write.secret, "traffic upd", "", 32));
        },
        else => return error.TlsIllegalParameter,
    }
}

fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const c: *Connection = @alignCast(@fieldParentPtr("writer", w));
    if (w.end > 0) try c.seal(.application_data, w.buffered());
    w.end = 0;
    var n: usize = 0;
    for (data[0 .. data.len - 1]) |bytes| if (bytes.len > 0) {
        try c.seal(.application_data, bytes);
        n += bytes.len;
    };
    const last = data[data.len - 1];
    if (last.len > 0) for (0..splat) |_| {
        try c.seal(.application_data, last);
        n += last.len;
    };
    return n;
}

fn flush(w: *Io.Writer) Io.Writer.Error!void {
    const c: *Connection = @alignCast(@fieldParentPtr("writer", w));
    if (w.end > 0) try c.seal(.application_data, w.buffered());
    w.end = 0;
    try c.output.flush();
}

test "an authority's server certificate verifies against it, for each name" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    const ca = try Authority.init(io, gpa, "werewolf test authority");
    const server = try ca.issue(io, gpa, &.{ "update.werewolf.test", "10.0.2.2" });
    const Certificate = std.crypto.Certificate;
    const now = @divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s);
    const root = try (Certificate{ .buffer = ca.der, .index = 0 }).parse();
    const leaf = try (Certificate{ .buffer = server.chain[0], .index = 0 }).parse();
    try leaf.verify(root, @intCast(now));
    try root.verify(root, @intCast(now));
    try leaf.verifyHostName("update.werewolf.test");
    try std.testing.expectError(
        error.CertificateHostMismatch,
        leaf.verifyHostName("other.werewolf.test"),
    );
    try std.testing.expect(mem.startsWith(u8, try ca.pem(gpa), "-----BEGIN CERTIFICATE-----\nMII"));
}

test "a ClientHello without TLS 1.3, x25519 or its signature is refused" {
    const good = helloBody(.{});
    _ = try parseHello(&good);
    try std.testing.expectError(
        error.TlsProtocolVersion,
        parseHello(&helloBody(.{ .version = 0x0303 })),
    );
    try std.testing.expectError(
        error.TlsHandshakeFailure,
        parseHello(&helloBody(.{ .group = 0x0017 })),
    );
    try std.testing.expectError(
        error.TlsHandshakeFailure,
        parseHello(&helloBody(.{ .scheme = 0x0804 })),
    );
    try std.testing.expectError(error.TlsDecodeError, parseHello(good[0 .. good.len - 1]));
}

/// helloBody is a ClientHello's body with one suite and three extensions.
fn helloBody(o: struct {
    version: u16 = 0x0304,
    group: u16 = 0x001d,
    scheme: u16 = 0x0403,
}) [100]u8 {
    const extensions = tls.extension(.supported_versions, [_]u8{2} ++ int(u16, o.version)) ++
        tls.extension(.signature_algorithms, int(u16, 2) ++ int(u16, o.scheme)) ++
        tls.extension(
            .key_share,
            int(u16, 36) ++ int(u16, o.group) ++ int(u16, 32) ++ @as([32]u8, @splat(9)),
        );
    return int(u16, 0x0303) ++ @as([32]u8, @splat(7)) ++ [_]u8{0} ++ int(u16, 2) ++
        int(u16, @backingInt(tls.CipherSuite.AES_128_GCM_SHA256)) ++ [_]u8{ 1, 0 } ++
        int(u16, extensions.len) ++ extensions;
}

test "std's TLS client completes a handshake and trades data both ways" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const io = std.testing.io;
    const ca = try Authority.init(io, gpa, "werewolf test authority");
    const identity = try ca.issue(io, gpa, &.{"127.0.0.1"});
    var address: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var served = try io.concurrent(serveOnce, .{ io, &listener, &identity });
    defer served.cancel(io) catch {};

    var bundle: std.crypto.Certificate.Bundle = .empty;
    const now = Io.Clock.real.now(io);
    try bundle.bytes.appendSlice(gpa, ca.der);
    try bundle.parseCert(gpa, 0, @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s)));
    var lock: Io.RwLock = .init;
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var in_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var out_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var reader = stream.reader(io, &in_buf);
    var writer = stream.writer(io, &out_buf);
    var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    var read_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var write_buf: [tls.Client.min_buffer_len]u8 = undefined;
    var client = try tls.Client.init(&reader.interface, &writer.interface, .{
        .host = .{ .explicit = "127.0.0.1" },
        .ca = .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &lock, .bundle = &bundle } },
        .read_buffer = &read_buf,
        .write_buffer = &write_buf,
        .entropy = &entropy,
        .realtime_now = now,
    });
    try client.writer.writeAll("ping");
    try client.writer.flush();
    try writer.interface.flush();
    try std.testing.expectEqualStrings("pong:ping", try client.reader.take(9));
    try served.await(io);
}

fn serveOnce(io: Io, listener: *Io.net.Server, identity: *const Identity) !void {
    const stream = try listener.accept(io);
    defer stream.close(io);
    var in_buf: [tls.max_ciphertext_record_len]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    var reader = stream.reader(io, &in_buf);
    var writer = stream.writer(io, &out_buf);
    var read_buf: [tls.max_ciphertext_len]u8 = undefined;
    var c: Connection = undefined;
    try c.accept(io, &reader.interface, &writer.interface, identity, &read_buf, &.{});
    const got = try c.reader.take(4);
    try c.writer.print("pong:{s}", .{got});
    try c.end();
}
