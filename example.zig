const std = @import("std");
const zpq = @import("zpq");

const statements = [_]zpq.Statement{
    .{
        .name = "hello_world",
        .query = "SELECT 7 * 191",
        .parameters = &[_]zpq.Oid{},
        .output = struct { hello: i32 },
    },
    .{
        .name = "math_stuff",
        .query = "SELECT $1 + $2, ($1::float / $2)::float4",
        .parameters = &[_]zpq.Oid{ .Int4, .Int4 },
        .output = struct { sum: i32, ratio: f32 },
    },
};

pub fn main() !void {
    var args = std.process.args();
    const name = args.nextPosix().?;
    const host = args.nextPosix() orelse return error.HostUnspecified;
    const user = args.nextPosix() orelse return error.UserUnspecified;
    const database = args.nextPosix() orelse return error.DatabaseUnspecified;
    const password = args.nextPosix();

    var con = try zpq.Connection(&statements).init(.{ .host = host, .database = database, .user = user, .password = password });
    defer con.deinit();

    var hello_query = try con.executeStatement("hello_world", .{});
    var hello_row = (try hello_query.fetchRow(null)).?;
    std.log.info("The magic number is {}", .{hello_row.hello});

    var math_query = try con.executeStatement("math_stuff", .{ 4, 7 });
    const math_row = (try math_query.fetchRow(null)).?;
    std.log.info("sum: {}, ratio: {d}", .{ math_row.sum, math_row.ratio });
}
