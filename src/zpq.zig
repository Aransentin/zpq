const builtin = @import("builtin");
const std = @import("std");
const Allocator = std.mem.Allocator;

const ConnectionArguments = struct {
    host: []const u8,
    database: []const u8,
    port: u16 = 5432,
    user: []const u8,
    password: ?[]const u8 = null,
    application_name: ?[]const u8 = null,
};

pub const Statement = struct {
    name: []const u8,
    query: []const u8,
    parameters: []const Oid,
    output: anytype,
};

pub const Oid = enum(u32) {
    Bool = 16,
    Char = 18,
    Int2 = 21,
    Int4 = 23,
    Int8 = 20,
    Bytea = 17,
    Text = 25,
    Json = 114,
    Float4 = 700,
    Float8 = 701,

    pub fn toZigType(self: Oid) type {
        return switch (self) {
            .Bool => bool,
            .Char => i8,
            .Int2 => i16,
            .Int4 => i32,
            .Int8 => i64,
            .Bytea => []const u8,
            .Text => []const u8,
            .Json => []const u8,
            .Float4 => f32,
            .Float8 => f64,
        };
    }
};

const Error = struct {
    code: [5]u8,
    severity: []const u8,
    message: []const u8,
    pos: u32,
};

fn parseError(data: []const u8) !Error {
    var err: Error = undefined;
    var p: usize = 0;
    while (data.len - p > 0 and data[p] != 0) {
        const zp = std.mem.indexOfScalarPos(u8, data, p + 1, 0) orelse return error.MalformedProtocolMessage;
        const val = data[p + 1 .. zp];
        switch (data[p]) {
            'S' => {
                err.severity = val;
            },
            'C' => {
                if (val.len != 5) return error.MalformedProtocolMessage;
                err.code = val[0..5].*;
            },
            'M' => {
                err.message = val;
            },
            'P' => {
                err.pos = (try std.fmt.parseUnsigned(u32, val, 10)) - 1;
            },
            else => {},
        }
        p += val.len + 2;
    }
    return err;
}

pub fn Connection(comptime statements: []const Statement) type {
    return struct {
        const Self = @This();
        file: std.fs.File,

        pub fn init(args: ConnectionArguments) !Self {
            if (args.database.len > 63)
                return error.DatabaseNameTooLong;
            if (args.user.len > 63)
                return error.UserNameTooLong;
            if (args.password != null and args.password.?.len > 1024)
                return error.PasswordTooLong;

            const file = blk: {
                if (@hasDecl(std.os, "sockaddr_un") and args.host.len > 1 and args.host[0] == '/') {
                    break :blk try std.net.connectUnixSocket(args.host);
                } else {
                    var abuf: [4096]u8 = undefined;
                    var alloc = std.heap.FixedBufferAllocator.init(abuf[0..]);
                    break :blk try std.net.tcpConnectToHost(&alloc.allocator, args.host, args.port);
                }
            };
            errdefer file.close();

            // Send handshake
            var startup_message: extern struct {
                len: u32 = undefined,
                version_number: u32 = std.mem.nativeToBig(u32, 196608),
                argbuf: ["user\x00".len + 64 + "database\x00".len + 64 + 1]u8 = undefined,
            } = .{};
            const nmsg = std.fmt.bufPrint(startup_message.argbuf[0..], "user\x00{}\x00database\x00{}\x00\x00", .{ args.user, args.database }) catch unreachable;
            const msglen: u32 = @intCast(u32, @sizeOf(u32) * 2 + nmsg.len);
            startup_message.len = std.mem.nativeToBig(u32, msglen);
            _ = try file.writeAll(std.mem.asBytes(&startup_message)[0..msglen]);

            var self = Self{
                .file = file,
            };

            // Parse the handshake reply
            var buf: [1024]u8 = undefined;
            var bp: usize = 0;
            var handshake_ok: bool = false;

            while (true) {
                const nb = try self.file.read(buf[0..]);
                if (nb == 0) return error.ConnectionClosed;
                bp += nb;

                var p: usize = 0;
                while (true) {
                    if (bp - p < 1 + 4)
                        break;

                    const mtype = buf[p];
                    const mlen = std.mem.readIntSliceBig(u32, buf[p + 1 .. p + 5]);
                    if (mlen < 4) return error.MalformedProtocolMessage;
                    if (bp - p < 1 + mlen) break;

                    switch (mtype) {
                        'R' => {
                            if (mlen < 8) return error.MalformedProtocolMessage;
                            const mspec = std.mem.readIntSliceBig(u32, buf[p + 5 .. p + 9]);
                            switch (mspec) {
                                0 => {}, // AuthenticationOk
                                5 => { // MD5 Password
                                    if (mlen != 12) return error.MalformedProtocolMessage;
                                    if (args.password) |password| {
                                        const salt = buf[p + 9 .. p + 13];
                                        var hashbuf: [1024 + 63]u8 = undefined;
                                        const hashme0 = std.fmt.bufPrint(hashbuf[0..], "{}{}", .{ args.password, args.user }) catch unreachable;
                                        var digest: [16]u8 = undefined;
                                        std.crypto.hash.Md5.hash(hashme0, digest[0..], .{});

                                        var hashme1: [32 + 4]u8 = undefined;
                                        _ = std.fmt.bufPrint(hashme1[0..32], "{x}", .{digest}) catch unreachable;
                                        std.mem.copy(u8, hashme1[32..], salt);
                                        std.crypto.hash.Md5.hash(hashme1[0..], digest[0..], .{});

                                        var fdigest: [36]u8 = undefined;
                                        _ = std.fmt.bufPrint(fdigest[0..], "md5{x}\x00", .{digest}) catch unreachable;

                                        const password_message: extern struct {
                                            type: [4]u8 = "\x00\x00\x00p".*, // The shit I have to do until packed structs work
                                            len: u32 = std.mem.nativeToBig(u32, 40),
                                            md5: [36]u8,
                                        } = .{ .md5 = fdigest };
                                        _ = try self.file.writeAll(std.mem.asBytes(&password_message)[3..44]);
                                    } else return error.AuthenticationRequired;
                                },
                                else => return error.UnsupportedAuthenticationMethod,
                            }
                        },
                        'S' => {
                            const nullp = std.mem.indexOfScalar(u8, buf[p + 5 .. p + 1 + mlen - 1], 0);
                            if (nullp) |np| {
                                const key = buf[p + 5 .. p + 5 + np];
                                const value = buf[p + 5 + np .. p + 1 + mlen - 1];
                                // std.debug.warn("{}: {}\n", .{ key, value });
                                // TODO: check for unicode and such
                            } else return error.MalformedProtocolMessage;
                        },
                        'K' => {
                            // TODO: get key & store it
                        },
                        'Z' => {
                            if (mlen != 5) return error.MalformedProtocolMessage;
                            handshake_ok = true;
                        },
                        'E' => {
                            const err = try parseError(buf[p + 5 .. p + 5 + mlen]);
                            std.log.err("{}: {}", .{ err.severity, err.message });

                            if (std.mem.eql(u8, err.code[0..], "28P01")) {
                                return error.InvalidPassword;
                            } else unreachable; // TODO: all the other ways auth can fail
                        },
                        else => unreachable,
                    }

                    p += 1 + mlen;
                }

                std.mem.copy(u8, buf[0 .. bp - p], buf[p..bp]);
                bp -= p;

                if (handshake_ok and bp == 0)
                    break;
            }

            // Generate the statements
            const sbuf: []const u8 = comptime blk: {
                var sbuf: []const u8 = &[0]u8{};
                inline for (statements) |stmnt| {
                    const evsize: usize = 4 + stmnt.name.len + 1 + stmnt.query.len + 1 + 2 + stmnt.parameters.len * 4;
                    sbuf = sbuf ++ [_]u8{'P'} ++ std.mem.asBytes(&std.mem.nativeToBig(u32, evsize));
                    sbuf = sbuf ++ stmnt.name ++ [_]u8{0};
                    sbuf = sbuf ++ stmnt.query ++ [_]u8{0};
                    sbuf = sbuf ++ std.mem.asBytes(&std.mem.nativeToBig(u16, stmnt.parameters.len));
                    inline for (stmnt.parameters) |param| {
                        sbuf = sbuf ++ std.mem.asBytes(&std.mem.nativeToBig(u32, @enumToInt(param)));
                    }
                    if (builtin.mode == .Debug) {
                        const evsize_desc: usize = 4 + 1 + stmnt.name.len + 1;
                        sbuf = sbuf ++ [_]u8{'D'} ++ std.mem.asBytes(&std.mem.nativeToBig(u32, evsize_desc));
                        sbuf = sbuf ++ [_]u8{'S'} ++ stmnt.name ++ [_]u8{0};
                    }
                }
                sbuf = sbuf ++ [_]u8{'S'} ++ std.mem.asBytes(&std.mem.nativeToBig(u32, 4)); // Sync
                break :blk sbuf;
            };
            _ = try self.file.writeAll(sbuf);

            // Create a slice of slices of the output Oids so we can index into it from a non-comptime variable
            const st_outputs = comptime blk: {
                var outp: []const []const Oid = &[0][]const Oid{};
                for (statements) |stmnt| {
                    var oids: []const Oid = &[0]Oid{};
                    for (@typeInfo(stmnt.output).Struct.fields) |val| {
                        const T = val.field_type;
                        oids = oids ++ switch (T) {
                            bool => &[1]Oid{Oid.Bool},
                            i8 => &[1]Oid{Oid.Char},
                            i16 => &[1]Oid{Oid.Int2},
                            i32 => &[1]Oid{Oid.Int4},
                            i64 => &[1]Oid{Oid.Int8},
                            f32 => &[1]Oid{Oid.Float4},
                            f64 => &[1]Oid{Oid.Float8},
                            else => @compileError("Return value type not yet implemented: " ++ @typeName(T)),
                        };
                    }
                    outp = outp ++ &[1][]const Oid{oids};
                }
                break :blk outp;
            };

            // ... also the names, for debugging
            const st_names = comptime blk: {
                var outp: []const []const u8 = &[0][]const u8{};
                for (statements) |stmnt| {
                    outp = outp ++ &[1][]const u8{stmnt.name};
                }
                break :blk outp;
            };

            // Parse the statement replies
            var statements_ok: usize = 0;
            var statements_ok_complete: bool = false;
            var failure_error: ?[5]u8 = null;
            bp = 0;
            while (true) {
                const nb = try self.file.read(buf[bp..]);
                if (nb == 0) return error.ConnectionClosed;
                bp += nb;

                var p: usize = 0;
                while (true) {
                    if (bp - p < 1 + 4)
                        break;

                    const mtype = buf[p];
                    const mlen = std.mem.readIntSliceBig(u32, buf[p + 1 .. p + 5]);
                    if (mlen < 4) return error.MalformedProtocolMessage;
                    if (bp - p < 1 + mlen) break;

                    switch (buf[p]) {
                        '1' => {
                            statements_ok += 1;
                        },
                        'E' => {
                            const err = try parseError(buf[p + 5 .. p + 5 + mlen]);
                            std.log.err("{}: {}", .{ err.severity, err.message });
                            failure_error = err.code;
                        },
                        'Z' => {
                            if (failure_error) |fail| {
                                if (std.mem.eql(u8, fail[0..], "42601")) {
                                    return error.SyntaxError;
                                } else if (std.mem.eql(u8, fail[0..], "42P01")) {
                                    return error.UndefinedTable;
                                } else unreachable; // TODO: All the zillion other possible errors
                            }
                            statements_ok_complete = true;
                        },
                        't' => {
                            if (builtin.mode != .Debug) unreachable;
                            // This data is just a copy of what we sent PostgreSQL above, so whatever
                        },
                        'T' => {
                            if (builtin.mode != .Debug) unreachable;
                            if (mlen < 6) return error.MalformedProtocolMessage;

                            const nfields = std.mem.readIntSliceBig(u16, buf[p + 5 .. p + 7]);
                            const outputs = st_outputs[statements_ok - 1];
                            if (outputs.len != nfields) {
                                std.log.err("Output mismatch for statement '{}': expected {} outputs, got {}", .{ st_names[statements_ok - 1], outputs.len, nfields });
                                return error.OutputTypeMismatch;
                            }
                            const fbuf = buf[p + 7 .. p + mlen + 1];
                            var pp: usize = 0;
                            var i: usize = 0;
                            while (i < nfields) : (i += 1) {
                                const nzero = std.mem.indexOfScalar(u8, fbuf[pp..], 0) orelse return error.MalformedProtocolMessage;
                                if (pp + nzero + 1 + 18 > fbuf.len) return error.MalformedProtocolMessage;

                                pp += nzero + 1 + 4 + 2; // Name, null byte, table Oid, column index -> we don't care
                                const oid = std.mem.readIntSliceBig(u32, fbuf[pp .. pp + 4]);
                                const expected_oid = st_outputs[statements_ok - 1][i];
                                if (oid != @enumToInt(st_outputs[statements_ok - 1][i])) {
                                    std.log.err("Oid mismatch for statement '{}': expected {} for output {}, got {}", .{ st_names[statements_ok - 1], expected_oid, i, @intToEnum(Oid, oid) });
                                    return error.OutputTypeMismatch;
                                }
                                pp += 4 + 2; // oid, column length

                                const tmod = std.mem.readIntSliceBig(i32, fbuf[pp .. pp + 4]);
                                pp += 4 + 2; // tmod, format
                            }
                        },
                        else => {
                            // TODO: Handle this?
                            unreachable;
                        },
                    }
                    p += 1 + mlen;
                }
                std.mem.copy(u8, buf[0 .. bp - p], buf[p..bp]);
                bp -= p;

                if (statements_ok_complete and bp == 0)
                    break;
            }

            return self;
        }

        pub fn deinit(self: *Self) void {
            if (self.file.handle == -1)
                return;
            const msg = [5]u8{ 'X', 0, 0, 0, 0x04 };
            _ = self.file.writeAll(msg[0..]) catch {};
            self.file.close();
        }

        fn getStatement(comptime statement_name: []const u8) Statement {
            inline for (statements) |stmnt| {
                if (std.mem.eql(u8, stmnt.name, statement_name))
                    return stmnt;
            }
            @compileError("The specified statement does not exist");
        }

        fn Query(comptime statement_name: []const u8) type {
            const statement = getStatement(statement_name);
            return struct {
                cnx: *Self,
                buf: std.io.BufferedReader(4096, std.fs.File.Reader),

                pub fn fetchRow(self: *@This(), allocator: ?*Allocator) !?statement.output {
                    var query_complete: bool = false;
                    var reader = self.buf.reader();

                    while (true) {
                        const mtype = try reader.readByte();
                        const len = try reader.readIntBig(u32);
                        switch (mtype) {
                            '2' => {}, // Bind completion, ignore
                            'C' => {
                                // Command completion, ignore
                                try reader.skipBytes(len - 4, .{ .buf_size = 64 });
                            },
                            'D' => {
                                // Data!
                                const nfields = try reader.readIntBig(u16);
                                // TODO: If debug, check that nfields is what we expect

                                var output: statement.output = undefined;

                                inline for (@typeInfo(statement.output).Struct.fields) |val| {
                                    const clen = try reader.readIntBig(u32);

                                    const T = val.field_type;
                                    switch (T) {
                                        bool => {
                                            if (builtin.mode == .Debug and clen != 1) return error.TypeLengthMismatch;
                                            @field(output, val.name) = (try reader.readByte()) == 1;
                                        },
                                        i8 => {
                                            if (builtin.mode == .Debug and clen != @sizeOf(i8)) return error.TypeLengthMismatch;
                                            @field(output, val.name) = try reader.readByte();
                                        },
                                        i16 => {
                                            if (builtin.mode == .Debug and clen != @sizeOf(i16)) return error.TypeLengthMismatch;
                                            @field(output, val.name) = try reader.readIntBig(i16);
                                        },
                                        i32 => {
                                            if (builtin.mode == .Debug and clen != @sizeOf(i32)) return error.TypeLengthMismatch;
                                            @field(output, val.name) = try reader.readIntBig(i32);
                                        },
                                        i64 => {
                                            if (builtin.mode == .Debug and clen != @sizeOf(i64)) return error.TypeLengthMismatch;
                                            @field(output, val.name) = try reader.readIntBig(i64);
                                        },
                                        f32 => {
                                            if (builtin.mode == .Debug and clen != @sizeOf(f32)) return error.TypeLengthMismatch;
                                            @field(output, val.name) = @bitCast(f32, try reader.readIntBig(u32));
                                        },
                                        f64 => {
                                            if (builtin.mode == .Debug and clen != @sizeOf(f64)) return error.TypeLengthMismatch;
                                            @field(output, val.name) = @bitCast(f64, try reader.readIntBig(u64));
                                        },
                                        u8, u16, u32, u64 => @compileError("PostgreSQL does not support unsigned variables: " ++ @typeName(T)),
                                        else => @compileError("Return value type yet implemented: " ++ @typeName(T)),
                                    }
                                }

                                return output;
                            },
                            'Z' => {
                                // Done
                                _ = try reader.readByte();
                                return null;
                            },
                            else => unreachable,
                        }
                    }

                    return null;
                }
            };
        }

        pub fn executeStatement(self: *Self, comptime statement_name: []const u8, params: anytype) !Query(statement_name) {
            if (@typeInfo(@TypeOf(params)) != .Struct) {
                @compileError("Expected tuple or struct argument, found " ++ @typeName(@TypeOf(args)));
            }

            const statement = getStatement(statement_name);
            if (params.len != statement.parameters.len) {
                @compileError("Number of parameters supplied does not match the number of statement parameters");
            }

            inline for (params) |param| {
                // TODO: check if param types are OK
            }

            const msglen = blk: {
                var len: usize = 4 + 1 + statement.name.len + 1; // message length, portal, statement
                len += if (statement.parameters.len > 0) 4 else 2; // param formats
                len += 2 + statement.parameters.len * 4; // number of parameters, parameter lengths
                inline for (params) |param, i| {
                    const T = if (@TypeOf(param) == comptime_int) statement.parameters[i].toZigType() else @TypeOf(param);
                    len += switch (T) {
                        // TODO: null is zero bytes
                        i8, i16, i32, i64, f32, f64 => @sizeOf(T),
                        u8, u16, u32, u64 => @compileError("PostgreSQL does not support unsigned variables: " ++ @typeName(T)),
                        else => @compileError("Parameter type not yet implemented: " ++ @typeName(T)),
                    };
                }
                len += if (@typeInfo(statement.output).Struct.fields.len > 0) 4 else 2;
                break :blk @intCast(u32, len);
            };

            var wbuf = std.io.bufferedWriter(self.file.writer());
            var writer = wbuf.writer();

            // Bind
            try writer.writeByte('B');
            try writer.writeIntBig(u32, msglen);
            try writer.writeByte(0);
            _ = try writer.writeAll(statement.name);
            try writer.writeByte(0);
            if (statement.parameters.len > 0) {
                try writer.writeIntBig(u16, 1);
                try writer.writeIntBig(u16, 1);
            } else {
                try writer.writeIntBig(u16, 0);
            }

            try writer.writeIntBig(u16, statement.parameters.len);
            inline for (params) |param, i| {
                const T = if (@TypeOf(param) == comptime_int) statement.parameters[i].toZigType() else @TypeOf(param);
                switch (T) {
                    i32 => {
                        try writer.writeIntBig(u32, 4);
                        try writer.writeIntBig(i32, param);
                    },
                    else => unreachable,
                }
            }

            if (@typeInfo(statement.output).Struct.fields.len > 0) {
                try writer.writeIntBig(u16, 1);
                try writer.writeIntBig(u16, 1);
            } else {
                try writer.writeIntBig(u16, 0);
            }

            // Execute
            try writer.writeByte('E');
            try writer.writeIntBig(u32, 9);
            try writer.writeByte(0);
            try writer.writeIntBig(u32, 0);

            // Sync
            try writer.writeByte('S');
            try writer.writeIntBig(u32, 4);

            // ...and flush!
            try wbuf.flush();
            return Query(statement_name){ .cnx = self, .buf = std.io.bufferedReader(self.file.reader()) };
        }
    };
}
