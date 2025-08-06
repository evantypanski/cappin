const std = @import("std");
const Pcap = @import("pcap.zig").Pcap;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) return error.ExpectedArgument;

    const file = try std.fs.cwd().openFile(args[1], .{ .mode = .read_only });
    defer file.close();
    var pcap = try Pcap.init(file, allocator);
    std.debug.print("Pcap with major version {d} and minor version {d}\n", .{ pcap.global_header.version_major, pcap.global_header.version_minor });

    var it = pcap.iterator();
    defer it.deinit();

    var count: usize = 0;
    while (try it.next()) |_| {
        count += 1;
    }

    std.debug.print("Found {d} records!\n", .{count});
}

test {
    @import("std").testing.refAllDecls(@This());
}
