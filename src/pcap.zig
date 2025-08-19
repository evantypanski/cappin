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
    // TODO: In the future, it would be nice to give an option to not
    // keep all records around, but it's easier for now so that the
    // iterator works multiple times without rereading the file
    records: []Record,
    reader: std.fs.File.Reader,

    global_header: GlobalHeader,

    pub fn init(file: std.fs.File, allocator: Allocator) !Self {
        var reader: std.fs.File.Reader = file.reader();
        const global_header = try GlobalHeader.init(&reader);
        var pcap: Self = .{
            .allocator = allocator,
            .records = &.{},
            .reader = reader,
            .global_header = global_header,
        };

        try pcap.populate_records();
        return pcap;
    }

    pub fn deinit(self: *Self) void {
        for (self.records) |record| {
            self.allocator.free(record.data);
        }
        self.allocator.free(self.records);
    }

    fn populate_records(self: *Self) !void {
        var records = std.ArrayList(Record).init(self.allocator);
        while (true) {
            var header_buf: [RecordHeader.Size]u8 = undefined;

            const read = try self.reader.readAll(&header_buf);

            // EOF
            if (read == 0) break;

            const header: RecordHeader = @bitCast(header_buf);

            // Now read the packet data
            var buffer = try std.ArrayList(u8).initCapacity(self.allocator, header.incl_len);
            buffer.items.len = header.incl_len;

            const read_packet = try self.reader.readAll(buffer.items);
            // EOF - TODO: Error here?
            if (read_packet == 0) break;

            var record = Record{
                .header = header,
                .eth_frame = null,
                .data = try buffer.toOwnedSlice(),
            };

            switch (self.global_header.network) {
                .ethernet => {
                    record.eth_frame = try EthernetFrame.init(record.data);
                },
                else => {},
            }

            try records.append(record);
        }

        self.records = try records.toOwnedSlice();
    }

    pub fn iterator(self: *Self) PcapIterator {
        return PcapIterator{
            .pcap = self,
        };
    }

    pub const PcapIterator = struct {
        pcap: *Pcap,
        pos: usize = 0,

        pub fn next(self: *PcapIterator) !?Record {
            if (self.pos >= self.pcap.records.len) return null;
            const record = self.pcap.records[self.pos];
            self.pos += 1;
            return record;
        }
    };
};

pub const LinkType = enum(u32) {
    null = 0,
    ethernet = 1,
    exp_ethernet = 2,
    _,
};

pub const GlobalHeader = packed struct {
    const Self = @This();
    const Size = @bitSizeOf(Self) / 8;

    magic_number: Magic,
    version_major: u16,
    version_minor: u16,
    thiszone: u32,
    sigfigs: u32,
    snaplen: u32,
    network: LinkType,

    pub fn init(reader: *std.fs.File.Reader) !Self {
        var buf: [Size]u8 = undefined;
        _ = try reader.readAll(&buf);
        return @bitCast(buf);
    }
};

pub const Record = struct {
    header: RecordHeader,
    // TODO: If more than ethernet gets supported this would
    // be a tagged union
    eth_frame: ?EthernetFrame,
    // The data within the record, including ALL protocols.
    data: []const u8,
};

pub const RecordHeader = packed struct {
    const Self = @This();
    const Size = @bitSizeOf(RecordHeader) / 8;

    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
};

pub const MacAddress = packed struct {
    const Self = @This();
    const Size = @bitSizeOf(RecordHeader) / 8;

    mac_one: u8,
    mac_two: u8,
    mac_three: u8,
    mac_four: u8,
    mac_five: u8,
    mac_six: u8,
};

pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    ipv6 = 0x86DD,
    _,
};

pub const EthernetHeader = packed struct {
    const Self = @This();
    const Size = @bitSizeOf(Self) / 8;

    dst_mac: MacAddress,
    src_mac: MacAddress,
    ethertype: EtherType,

    pub fn init(data: [14]u8) !EthernetHeader {
        return .{
            .dst_mac = @bitCast(data[0..6].*),
            .src_mac = @bitCast(data[6..12].*),
            .ethertype = @enumFromInt(std.mem.readInt(u16, data[12..14], .big)),
        };
    }
};

pub const EthernetFrame = struct {
    header: EthernetHeader,
    ipv4_packet: ?IPV4Packet,

    // The raw payload
    payload: []const u8,

    pub fn init(data: []const u8) !EthernetFrame {
        const header = try EthernetHeader.init(data[0..EthernetHeader.Size].*);

        var ipv4_packet: ?IPV4Packet = null;
        const payload = data[EthernetHeader.Size..];
        if (header.ethertype == .ipv4) {
            ipv4_packet = try IPV4Packet.init(payload);
        }

        return EthernetFrame{
            .header = header,
            .ipv4_packet = ipv4_packet,
            .payload = payload,
        };
    }
};

pub const IPV4Packet = struct {
    header: IPV4Header,
    payload: []const u8,

    pub fn init(data: []const u8) !IPV4Packet {
        return .{
            .header = try IPV4Header.init(data),
            .payload = data[@sizeOf(IPV4Header)..],
        };
    }
};

pub const Protocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    _,
};

// TODO: Byte order, think that's based on the pcap.
pub const IPV4Header = packed struct {
    const Self = @This();
    const Size = @bitSizeOf(Self) / 8;

    version: u4,
    ihl: u4,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: Protocol,
    check: u16,
    saddr: u32,
    daddr: u32,

    pub fn init(data: []const u8) !IPV4Header {
        return @bitCast(data[0..Size].*);
    }
};

test "Basic headers" {
    const file = try std.fs.cwd().openFile("test/http.pcap", .{ .mode = .read_only });
    defer file.close();

    var pcap = try Pcap.init(file, std.testing.allocator);
    defer pcap.deinit();
    // Just sanity check the magic number and packet numbers
    try std.testing.expectEqual(pcap.global_header.magic_number, Magic.tcpdump);
    try std.testing.expectEqual(pcap.global_header.network, LinkType.ethernet);

    var it = pcap.iterator();

    var count: usize = 0;
    while (try it.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(count, 43);
}
