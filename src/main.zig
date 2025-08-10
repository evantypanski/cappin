const std = @import("std");
const Pcap = @import("pcap.zig").Pcap;
const Model = @import("tui.zig").Model;
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) return error.ExpectedArgument;

    const file = try std.fs.cwd().openFile(args[1], .{ .mode = .read_only });
    defer file.close();
    var pcap = try Pcap.init(file, allocator);
    std.debug.print("Pcap with major version {d} and minor version {d}\n", .{ pcap.global_header.version_major, pcap.global_header.version_minor });

    var app = try vxfw.App.init(allocator);
    defer app.deinit();

    const model = try allocator.create(Model);
    defer allocator.destroy(model);

    // Set the initial state of our button
    model.* = .{
        .pcap = &pcap,
        .count = 0,
        .button = .{
            .label = "Click me!",
            .onClick = Model.onClick,
            .userdata = model,
        },
    };

    try app.run(model.widget(), .{});
}

test {
    @import("std").testing.refAllDecls(@This());
}
