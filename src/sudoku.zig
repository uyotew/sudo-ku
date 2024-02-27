const std = @import("std");

pub fn playSudoku(cells_given: u8) !bool {
    const rng = blk: {
        const seed: u64 = @intCast(std.time.nanoTimestamp());
        var def_rng = std.rand.DefaultPrng.init(seed);
        break :blk def_rng.random();
    };

    const r = std.io.getStdIn().reader();
    const w = std.io.getStdOut().writer();

    try w.writeAll("generating sudoku...");
    var sudoku = try Sudoku.generate(cells_given, rng);
    try w.writeAll("\x1b[G");

    const termios = try initTerm();
    try w.writeAll("\x1b[?25l");

    var status: enum { Valid, Quit, Playing, Invalid } = .Playing;
    while (status == .Playing or status == .Invalid) {
        try sudoku.print();
        try w.print("enter: validate  {s}\n", .{
            if (status == .Invalid) ":(" else "  ",
        });
        status = .Playing;
        switch (try r.readByte()) {
            'h' => sudoku.pos.left(),
            'j' => sudoku.pos.down(),
            'k' => sudoku.pos.up(),
            'l' => sudoku.pos.right(),
            '1'...'9' => |c| sudoku.setNum(c - '0'),
            '0', ' ' => sudoku.clearNum(),
            '\n' => status = if (sudoku.valid(false)) .Valid else .Invalid,
            'r' => sudoku.reset(),
            'g' => blk: {
                const row = switch (try r.readByte()) {
                    '1'...'9' => |c| c - '1',
                    else => break :blk,
                };
                const col = switch (try r.readByte()) {
                    '1'...'9' => |c| c - '1',
                    else => break :blk,
                };
                sudoku.pos.row = row;
                sudoku.pos.col = col;
            },
            'q' => status = .Quit,
            else => {},
        }
        // move cursor back and clear screen
        try w.writeAll("\x1b[14A");
        try w.writeAll("\x1b[G");
        try w.writeAll("\x1b[J");
    }
    try std.os.tcsetattr(0, .FLUSH, termios);
    try w.writeAll("\x1b[?25h");
    return status == .Valid;
}

fn initTerm() !std.os.termios {
    const fd = 0;
    const os = std.os;
    if (!os.isatty(fd)) return error.NotATty;
    const original_termios = try os.tcgetattr(fd);

    var termios = original_termios;
    termios.lflag &= ~@as(
        os.tcflag_t,
        os.linux.ECHO | os.linux.ICANON | os.linux.ISIG | os.linux.IEXTEN,
    );
    termios.cc[os.linux.V.TIME] = 0;
    termios.cc[os.linux.V.MIN] = 1;
    try os.tcsetattr(fd, .FLUSH, termios);
    return original_termios;
}

const Sudoku = struct {
    grid: [9][9]?Cell,
    pos: Pos = .{},

    const Cell = struct { given: bool, val: u8 };
    const Pos = struct {
        row: u8 = 0,
        col: u8 = 0,

        pub fn left(self: *Pos) void {
            self.col = if (self.col == 0) 8 else self.col - 1;
        }

        pub fn right(self: *Pos) void {
            self.col = if (self.col == 8) 0 else self.col + 1;
        }

        pub fn up(self: *Pos) void {
            self.row = if (self.row == 0) 8 else self.row - 1;
        }

        pub fn down(self: *Pos) void {
            self.row = if (self.row == 8) 0 else self.row + 1;
        }
    };

    /// creating a sudoku, with brute force
    /// will always fail at generating a sudoku with fewer given cells than 17
    /// runtime increases with fewer given cells
    pub fn generate(cells_given: u8, rng: std.rand.Random) !Sudoku {
        var unused: [81][9]bool = undefined;
        for (&unused) |*cell| @memset(cell, true);
        var s = Sudoku{ .grid = [_][9]?Cell{[_]?Cell{null} ** 9} ** 9 };
        if (!s.solve(&unused, rng, 0)) return error.FailedToGenerateSudoku;

        for (s.grid[0..]) |*row| {
            for (row[0..]) |*cell| {
                if (cell.*) |*c| c.given = true;
            }
        }

        // this could be made to backtrack.. but probably wont
        const n_removed = if (cells_given > 81) 0 else 81 - cells_given;
        var to_try: [81]u8 = undefined;
        for (&to_try, 0..) |*c, i| c.* = @intCast(i);
        var i: u8 = 0;
        while (i < n_removed) {
            rng.shuffle(u8, &to_try);
            for (to_try) |n| {
                const cell = &s.grid[n / 9][n % 9];
                if (cell.* == null) continue;
                const old_cell = cell.*;
                cell.* = null;
                if (s.isUnique(rng)) {
                    i += 1;
                    break;
                } else cell.* = old_cell;
            } else return error.FailedToGenerateSudoku;
        }
        return s;
    }

    fn rowValid(self: Sudoku, i: u8, empty_ok: bool) bool {
        var lst: [9]bool = undefined;
        @memset(&lst, false);

        for (self.grid[i]) |cell| {
            if (cell) |c| {
                if (lst[c.val - 1] == true) return false else lst[c.val - 1] = true;
            } else if (!empty_ok) return false;
        }
        return true;
    }

    fn colValid(self: Sudoku, j: u8, empty_ok: bool) bool {
        var lst: [9]bool = undefined;
        @memset(&lst, false);

        for (0..9) |i| {
            const cell = self.grid[i][j];
            if (cell) |c| {
                if (lst[c.val - 1] == true) return false else lst[c.val - 1] = true;
            } else if (!empty_ok) return false;
        }
        return true;
    }

    fn boxValid(self: Sudoku, row: u8, col: u8, empty_ok: bool) bool {
        var lst: [9]bool = undefined;
        @memset(&lst, false);
        const br = (row / 3) * 3;
        const bc = (col / 3) * 3;

        for (br..br + 3) |i| {
            for (bc..bc + 3) |j| {
                const cell = self.grid[i][j];
                if (cell) |c| {
                    if (lst[c.val - 1] == true) return false else lst[c.val - 1] = true;
                } else if (!empty_ok) return false;
            }
        }
        return true;
    }

    fn valid(self: Sudoku, empty_ok: bool) bool {
        for (0..9) |i| {
            if (!self.rowValid(@intCast(i), empty_ok)) return false;
            if (!self.colValid(@intCast(i), empty_ok)) return false;
            if (!self.boxValid(@intCast(i), @intCast(i * 3 % 9), empty_ok)) return false;
        }
        return true;
    }

    // returns false if no solution
    // start_idx should at most be 80
    fn solve(self: *Sudoku, unused: *[81][9]bool, rng: std.rand.Random, start_idx: u8) bool {
        var i: struct {
            idx: u8,
            dir: enum(i2) { Fwd = 1, Bck = -1, Cnt = 0 } = .Cnt,
            pub fn next(this: *@This()) bool {
                if (this.idx == 0 and this.dir == .Bck) return false;
                this.idx = @intCast(@as(i16, this.idx) + @intFromEnum(this.dir));
                return this.idx < 81;
            }
        } = .{ .idx = start_idx };
        while (i.next()) {
            const cell = &self.grid[i.idx / 9][i.idx % 9];
            if (cell.*) |c| if (c.given) {
                if (i.dir == .Cnt) i.dir = .Fwd;
                continue;
            };

            const new_val = blk: {
                const ri = rng.uintLessThan(u8, 9);
                for (0..9) |n| if (unused[i.idx][(ri + n) % 9]) break :blk (ri + n) % 9;
                break :blk null;
            };
            if (new_val) |v| {
                unused[i.idx][v] = false;
                cell.* = Cell{ .val = @intCast(v + 1), .given = false };
                i.dir = if (self.valid(true)) .Fwd else .Cnt;
            } else {
                cell.* = null;
                @memset(&unused[i.idx], true);
                i.dir = .Bck;
            }
        }
        return i.dir == .Fwd;
    }

    fn isUnique(self: Sudoku, rng: std.rand.Random) bool {
        var unused: [81][9]bool = undefined;
        for (&unused) |*cell| @memset(cell, true);
        var temp = self;
        const first_sol = temp.solve(&unused, rng, 0);
        const begin_idx: u8 = for (0..81) |d| {
            const i: u8 = @truncate(80 - d);
            if (temp.grid[i / 9][i % 9]) |c| if (!c.given) break i;
        } else unreachable;
        const second_sol = temp.solve(&unused, rng, begin_idx);
        return !(first_sol and second_sol);
    }

    fn setNum(self: *Sudoku, n: u8) void {
        if (self.grid[self.pos.row][self.pos.col]) |*cell| {
            if (!cell.given) cell.val = n;
        } else self.grid[self.pos.row][self.pos.col] = Cell{ .val = n, .given = false };
    }

    fn clearNum(self: *Sudoku) void {
        if (self.grid[self.pos.row][self.pos.col]) |cell| {
            if (!cell.given) self.grid[self.pos.row][self.pos.col] = null;
        }
    }
    fn reset(self: *Sudoku) void {
        for (self.grid[0..]) |*row| {
            for (row[0..]) |*cell| {
                if (cell.*) |c| {
                    if (!c.given) cell.* = null;
                }
            }
        }
    }

    fn print(self: Sudoku) !void {
        const line = ("-" ** 25) ++ "\n";
        const writer = std.io.getStdOut().writer();

        for (self.grid, 0..) |row, i| {
            if (i % 3 == 0) try writer.writeAll(line);
            for (row, 0..) |cell, j| {
                if (j % 3 == 0) try writer.writeAll("| ");
                if (self.pos.row == i and self.pos.col == j) try writer.writeAll("\x1b[7m");
                if (cell) |c| if (c.given) try writer.writeAll("\x1b[36m");
                try writer.print("{c}", .{if (cell) |c| c.val + '0' else ' '});
                try writer.writeAll("\x1b[0m ");
            }
            try writer.writeAll("|  ");
            if (i == 0) try writer.writeAll(" [1-9]:       put number");
            if (i == 2) try writer.writeAll(" space:       remove number");
            if (i == 3) try writer.writeAll(" hjkl:        move");
            if (i == 5) try writer.writeAll(" g[1-9][1-9]: go to row,column");
            if (i == 6) try writer.writeAll(" r:           reset");
            if (i == 8) try writer.writeAll(" q:           quit");
            try writer.writeAll("\n");
        }
        try writer.writeAll(line);
    }
};
