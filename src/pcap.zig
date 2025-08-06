//! Central data structures for a pcap and its headers.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

pub const Magic = enum(u32) {
    tcpdump = 0xA1B2C3D4,
    byte_order = 0x1A2B3C4D,
    kuznetzov_tcpdump = 0xA1B2CD34,
    fmesquita_tcpdump = 0xA1B234CD,
    navtel_tcpdump = 0xA12B3C4D,
    nsec_tcpdump = 0xA1B23C4D,
    cbpf_savefile = 0xA1B2C3CB,
    _,
};

pub const Pcap = struct {
    const Self = @This();

    allocator: Allocator,
    reader: std.fs.File.Reader,

    global_header: GlobalHeader,

    pub fn init(file: std.fs.File, allocator: Allocator) !Self {
        var reader = file.reader();
        const global_header = try GlobalHeader.init(&reader);
        return .{
            .allocator = allocator,
            .reader = reader,
            .global_header = global_header,
        };
    }

    pub fn iterator(self: *Self) PcapIterator {
        return PcapIterator{
            .pcap = self,
            .buffer = std.ArrayList(u8).init(self.allocator),
        };
    }

    pub const PcapIterator = struct {
        pcap: *Pcap,
        buffer: std.ArrayList(u8),

        pub const Record = struct {
            header: RecordHeader,
            data: []const u8,
        };

        pub fn deinit(self: *PcapIterator) void {
            self.buffer.deinit();
        }

        pub fn next(self: *PcapIterator) !?Record {
            var header_buf: [(@bitSizeOf(RecordHeader) / 8)]u8 = undefined;

            const read = try self.pcap.reader.readAll(&header_buf);

            // EOF
            if (read == 0) return null;

            const header: RecordHeader = @bitCast(header_buf);

            // Now read the packet data
            // TODO: Is the clear necessary?
            self.buffer.clearRetainingCapacity();
            try self.buffer.ensureTotalCapacity(header.incl_len);
            self.buffer.items.len = header.incl_len;

            const read_packet = try self.pcap.reader.readAll(self.buffer.items);
            // EOF
            if (read_packet == 0) return null;

            return Record{
                .header = header,
                .data = self.buffer.items,
            };
        }
    };
};

pub const GlobalHeader = packed struct {
    const Self = @This();

    magic_number: Magic,
    version_major: u16,
    version_minor: u16,
    thiszone: u32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,

    pub fn init(reader: *std.fs.File.Reader) !Self {
        var buf: [(@bitSizeOf(GlobalHeader) / 8)]u8 = undefined;
        _ = try reader.readAll(&buf);
        return @bitCast(buf);
    }
};

pub const RecordHeader = packed struct {
    const Self = @This();

    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
};

test "Basic headers" {
    const file = try std.fs.cwd().openFile("test/http.pcap", .{ .mode = .read_only });
    defer file.close();

    var pcap = try Pcap.init(file, std.testing.allocator);
    // Just sanity check the magic number and packet numbers
    try std.testing.expectEqual(pcap.global_header.magic_number, Magic.tcpdump);

    var it = pcap.iterator();
    defer it.deinit();

    var count: usize = 0;
    while (try it.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(count, 43);
}
