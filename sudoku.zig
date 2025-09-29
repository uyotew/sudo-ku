const std = @import("std");

pub fn playSudoku(cells_given: u8, r: *std.Io.Reader, w: *std.Io.Writer) !bool {
    const seed: u64 = @intCast(std.time.nanoTimestamp());
    var rng_state = std.Random.DefaultPrng.init(seed);
    const rng = rng_state.random();

    try w.writeAll("generating sudoku...");
    try w.flush();
    var sudoku: Sudoku = try .generate(cells_given, rng);
    try w.writeAll("\x1b[G"); // move cursor to start of line

    const stdin: std.fs.File = .stdin();
    const original_termios = try std.posix.tcgetattr(stdin.handle);
    var termios = original_termios;
    termios.lflag.ECHO = false;
    termios.lflag.ICANON = false;
    termios.lflag.ISIG = false;
    termios.lflag.IEXTEN = false;
    termios.cc[@intFromEnum(std.os.linux.V.TIME)] = 0;
    termios.cc[@intFromEnum(std.os.linux.V.MIN)] = 1;
    try std.posix.tcsetattr(stdin.handle, .FLUSH, termios);

    defer std.posix.tcsetattr(stdin.handle, .FLUSH, original_termios) catch
        std.log.warn("failed to reset terminal", .{});

    try w.writeAll("\x1b[?25l"); // hide cursor

    var row: u8, var col: u8 = .{ 0, 0 };

    var status: enum { valid, quit, playing, invalid } = .playing;
    while (status == .playing or status == .invalid) {
        const line = ("-" ** 25) ++ "\n";
        for (0..9) |i| {
            if (i % 3 == 0) try w.writeAll(line);
            for (0..9) |j| {
                if (j % 3 == 0) try w.writeAll("| ");
                if (row == i and col == j) try w.writeAll("\x1b[7m");
                const cell = sudoku.grid[i * 9 + j];
                if (cell.isGiven()) try w.writeAll("\x1b[36m");
                try w.writeByte(if (cell == .empty) ' ' else cell.toInt() + '0');
                try w.writeAll("\x1b[0m ");
            }
            try w.writeAll("|  ");
            if (i == 0) try w.writeAll(" [1-9]:       put number");
            if (i == 2) try w.writeAll(" space, 0:    remove number");
            if (i == 3) try w.writeAll(" hjkl:        move");
            if (i == 5) try w.writeAll(" g[1-9][1-9]: go to row,column");
            if (i == 6) try w.writeAll(" r:           reset");
            if (i == 8) try w.writeAll(" q:           quit");
            try w.writeAll("\n");
        }
        try w.writeAll(line);

        try w.print("enter: validate  {s}\n", .{
            if (status == .invalid) ":(" else "  ",
        });
        try w.flush();

        status = .playing;
        switch (try r.takeByte()) {
            'h' => col = if (col == 0) 8 else col - 1,
            'j' => row = if (row == 8) 0 else row + 1,
            'k' => row = if (row == 0) 8 else row - 1,
            'l' => col = if (col == 8) 0 else col + 1,
            '1'...'9' => |c| sudoku.setNumAt(row, col, c - '0'),
            '0', ' ' => sudoku.clearNumAt(row, col),
            '\n' => status = if (sudoku.isCompleted()) .valid else .invalid,
            'r' => sudoku.reset(),
            'g' => blk: {
                const new_row = switch (try r.takeByte()) {
                    '1'...'9' => |c| c - '1',
                    else => break :blk,
                };
                const new_col = switch (try r.takeByte()) {
                    '1'...'9' => |c| c - '1',
                    else => break :blk,
                };
                row, col = .{ new_row, new_col };
            },
            'q' => status = .quit,
            else => {},
        }
        try w.writeAll("\x1b[14F\x1b[J"); // move 14 lines up and clear screen
    }
    try w.writeAll("\x1b[?25h"); // show cursor
    try w.flush();
    return status == .valid;
}

const Sudoku = struct {
    // row-major order
    grid: [9 * 9]Cell,

    const Cell = enum(u5) {
        empty = 0,
        // 1...9 are normal values
        given_flag = 10,
        // 11...19 are 'given' values
        _,

        fn given(n: u5) Cell {
            std.debug.assert(n > 0 and n < 10);
            return @enumFromInt(n + @intFromEnum(Cell.given_flag));
        }

        fn isGiven(c: Cell) bool {
            return @intFromEnum(c) > @intFromEnum(Cell.given_flag);
        }

        fn toInt(c: Cell) u8 {
            std.debug.assert(c != .empty);
            const n = @intFromEnum(c);
            if (c.isGiven()) return n - @intFromEnum(Cell.given_flag);
            return n;
        }
    };

    fn setNumAt(s: *Sudoku, row: u8, col: u8, n: u8) void {
        const cell = &s.grid[row * 9 + col];
        if (!cell.isGiven()) cell.* = @enumFromInt(n);
    }

    fn clearNumAt(s: *Sudoku, row: u8, col: u8) void {
        const cell = &s.grid[row * 9 + col];
        if (!cell.isGiven()) cell.* = .empty;
    }
    fn reset(s: *Sudoku) void {
        for (&s.grid) |*cell| {
            if (!cell.isGiven()) cell.* = .empty;
        }
    }

    /// sudokus can't have fewer given cells than 17
    /// runtime increases with fewer given cells
    fn generate(cells_given: u8, rng: std.Random) error{GenerationFailed}!Sudoku {
        std.debug.assert(cells_given >= 17 and cells_given < 81);
        var used: [9 * 9]u9 = undefined;
        @memset(&used, 0);
        var s = Sudoku{ .grid = undefined };
        @memset(&s.grid, .empty);

        switch (s.solve(&used, rng)) {
            .no_solution => unreachable,
            .solved => {},
        }
        for (&s.grid) |*cell| cell.* = .given(@intFromEnum(cell.*));

        var indices: [9 * 9]u8 = undefined;
        for (&indices, 0..) |*e, i| e.* = @intCast(i);
        var to_remove: u8 = 9 * 9 - cells_given;
        while (to_remove > 0) : (to_remove -= 1) {
            rng.shuffle(u8, &indices);
            for (&indices) |i| {
                if (s.grid[i] == .empty) continue;
                const old_cell = s.grid[i];
                s.grid[i] = .empty;
                if (s.hasUniqueSolution(rng)) break;
                s.grid[i] = old_cell;
            } else return error.GenerationFailed;
        }
        return s;
    }

    // sudoku must have some given cells for this to be useful
    // returns true if only one or no solutions exist
    // TODO: this could be non-random, just pick the next unused number
    fn hasUniqueSolution(s: *const Sudoku, rng: std.Random) bool {
        var used: [9 * 9]u9 = undefined;
        @memset(&used, 0);
        var copy = s.*;
        if (copy.solve(&used, rng) == .no_solution) return true;
        var i: usize = 9 * 9;
        while (i > 0) {
            i -= 1;
            if (!copy.grid[i].isGiven()) break;
        }
        return copy.solveFrom(&used, rng, i) == .no_solution;
    }

    const SolveResult = enum { solved, no_solution };

    fn solve(s: *Sudoku, used: *[9 * 9]u9, rng: std.Random) SolveResult {
        return s.solveFrom(used, rng, 0);
    }

    fn solveFrom(s: *Sudoku, used: *[9 * 9]u9, rng: std.Random, i_init: usize) SolveResult {
        std.debug.assert(s.valid());
        var i = i_init;
        while (i < 9 * 9) : (i += 1) {
            if (s.grid[i].isGiven()) continue;
            if (s.setRandomValidCell(i, &used[i], rng)) continue;
            used[i] = 0;
            s.grid[i] = .empty;
            while (i != 0) {
                i -= 1;
                if (s.grid[i].isGiven()) continue;
                if (s.setRandomValidCell(i, &used[i], rng)) break;
                used[i] = 0;
                s.grid[i] = .empty;
            } else return .no_solution;
        }
        return .solved;
    }

    fn setRandomValidCell(s: *Sudoku, i: usize, used: *u9, rng: std.Random) bool {
        while (used.* != 0b111_111_111) {
            var free_idx = rng.uintLessThan(u8, 9 - @popCount(used.*)) + 1;
            const n = for (0..9) |k| {
                if (used.* & (@as(u9, 1) << @intCast(k)) == 0) free_idx -= 1;
                if (free_idx == 0) break k;
            } else unreachable;
            used.* |= @as(u9, 1) << @intCast(n);
            s.grid[i] = @enumFromInt(n + 1);
            if (s.cellIndexValid(i)) return true;
        }
        return false;
    }

    fn isCompleted(s: *const Sudoku) bool {
        for (&s.grid) |cell| if (cell == .empty) return false;
        return if (s.valid()) true else false;
    }

    fn valid(s: *const Sudoku) bool {
        for (0..9) |n| {
            if (!s.rowValid(@intCast(n))) return false;
            if (!s.colValid(@intCast(n))) return false;
            if (!s.boxValid(@intCast(n))) return false;
        }
        return true;
    }

    fn cellIndexValid(s: *const Sudoku, i: usize) bool {
        const row: u8 = @intCast(i / 9);
        const col: u8 = @intCast(i % 9);
        if (!s.rowValid(row)) return false;
        if (!s.colValid(col)) return false;
        if (!s.boxValid(((row / 3) * 3) + (col / 3))) return false;
        return true;
    }

    fn cellSeen(seen: *u9, cell: Cell) bool {
        if (cell == .empty) return false;
        const mask: u9 = @as(u9, 1) << @intCast(cell.toInt() - 1);
        if (mask & seen.* != 0) return true;
        seen.* |= mask;
        return false;
    }

    fn rowValid(s: *const Sudoku, row: u8) bool {
        var seen: u9 = 0;
        for (s.grid[row * 9 ..][0..9]) |cell| {
            if (cellSeen(&seen, cell)) return false;
        }
        return true;
    }

    fn colValid(s: *const Sudoku, col: u8) bool {
        var seen: u9 = 0;
        for (0..9) |row| {
            if (cellSeen(&seen, s.grid[row * 9 + col])) return false;
        }
        return true;
    }

    fn boxValid(s: *const Sudoku, n: u8) bool {
        var seen: u9 = 0;
        const row_start = (n / 3) * 3;
        const col_start = (n % 3) * 3;
        for (row_start..row_start + 3) |row| {
            for (col_start..col_start + 3) |col| {
                if (cellSeen(&seen, s.grid[row * 9 + col])) return false;
            }
        }
        return true;
    }
};
