const std = @import("std");
const Pcap = @import("pcap.zig").Pcap;
const tui = @import("tui.zig").tui;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) return error.ExpectedArgument;

    const file = try std.fs.cwd().openFile(args[1], .{ .mode = .read_only });
    defer file.close();
    var pcap = try Pcap.init(file, allocator);

    try tui(allocator, &pcap);
}

test {
    @import("std").testing.refAllDecls(@This());
}
