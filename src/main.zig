const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        std.log.err("Usage: {s} <program>", .{args[0]});
        return error.BadArgCount;
    }

    var program_file = try std.fs.cwd().openFile(args[1], .{});
    defer program_file.close();

    try setup_interpret(program_file, allocator);
}

// `std.math.big.int`s are too unwieldy for this
const Nat = u256;

fn setup_interpret(program: std.fs.File, allocator: std.mem.Allocator) !void {
    var registers: [3]Nat = .{ 0, 0, 0 };

    var stacks: [2]*std.ArrayList(Nat) = undefined;

    stacks[0] = @constCast(&std.ArrayList(Nat).init(allocator));
    defer stacks[0].deinit();
    stacks[1] = @constCast(&std.ArrayList(Nat).init(allocator));
    defer stacks[1].deinit();

    try interpret(
        program,
        allocator,
        &registers,
        &stacks,
    );
}

const Command = enum(u8) {
    dw_not = '~', // (base - 1) - a
    dw_or = '|', // min(a + b, (base - 1))
    dw_xor = '^', // (a + b) mod base
    dw_and = '&', // min(a * b, (base - 1))
    dw_mand = '*', // (a * b) mod base

    shift_left = '<', // A * pow(base, B)
    shift_right = '>', // floor(A / pow(base, B))

    digit_count = '/',

    set_base = '_',

    swap_stacks = '$',
    cycle_registers = '%',

    push_a = '@',
    pop_a = '!',
    push_0 = '0',
    push_1 = '1',

    skip_block = '?',
    loop_block = '"',
    start_block = '(',
    end_block = ')',

    input = 'i',
    output = 'o',

    comment = '#',

    _,
};

const RegisterId = enum(u2) {
    a,
    b,
    c,
};

fn interpret(
    program: std.fs.File,
    allocator: std.mem.Allocator,
    registers: *[3]Nat,
    stacks: *[2]*std.ArrayList(Nat),
) !void {
    const stdin = std.io.getStdIn().reader();
    const stdout = std.io.getStdOut().writer();

    var blocks = std.ArrayList(usize).init(allocator);
    defer blocks.deinit();

    var base: Nat = 2;

    // which register is treated as A
    var a_register: u2 = 0;
    // which stack is treated as X
    var x_stack: u1 = 0;

    const program_reader = program.reader();
    const seekable_program = program.seekableStream();

    while (program_reader.readByte() catch null) |byte| {
        // TODO: better error handling
        errdefer {
            const stderr = std.io.getStdErr().writer();

            stderr.print(
                "Error at index {d}: {c}\n",
                .{
                    // if you have a larger file, you have bigger problems
                    @as(
                        i64,
                        @intCast(seekable_program.getPos() catch std.math.maxInt(u64)),
                    ),
                    byte,
                },
            ) catch {};
        }
        const command: Command = @enumFromInt(byte);
        switch (command) {
            .dw_not => {
                try push(
                    stacks[x_stack],
                    try dwNot(
                        registers[getRegisterId(.a, a_register)],
                        registers[getRegisterId(.c, a_register)],
                        base,
                    ),
                );
            },
            .dw_or => {
                try push(
                    stacks[x_stack],
                    try dwOr(
                        registers[getRegisterId(.a, a_register)],
                        registers[getRegisterId(.b, a_register)],
                        registers[getRegisterId(.c, a_register)],
                        base,
                    ),
                );
            },
            .dw_xor => {
                try push(
                    stacks[x_stack],
                    try dwXor(
                        registers[getRegisterId(.a, a_register)],
                        registers[getRegisterId(.b, a_register)],
                        registers[getRegisterId(.c, a_register)],
                        base,
                    ),
                );
            },
            .dw_and => {
                try push(
                    stacks[x_stack],
                    try dwAnd(
                        registers[getRegisterId(.a, a_register)],
                        registers[getRegisterId(.b, a_register)],
                        registers[getRegisterId(.c, a_register)],
                        base,
                    ),
                );
            },
            .dw_mand => {
                try push(
                    stacks[x_stack],
                    try dwMand(
                        registers[getRegisterId(.a, a_register)],
                        registers[getRegisterId(.b, a_register)],
                        registers[getRegisterId(.c, a_register)],
                        base,
                    ),
                );
            },
            .shift_left => {
                try push(
                    stacks[x_stack],
                    try shiftLeft(
                        registers[getRegisterId(.a, a_register)],
                        registers[getRegisterId(.b, a_register)],
                        base,
                    ),
                );
            },
            .shift_right => {
                try push(
                    stacks[x_stack],
                    try shiftRight(
                        registers[getRegisterId(.a, a_register)],
                        registers[getRegisterId(.b, a_register)],
                        base,
                    ),
                );
            },
            .digit_count => {
                try push(
                    stacks[x_stack],
                    try digitCount(
                        registers[getRegisterId(.a, a_register)],
                        base,
                    ),
                );
            },
            .set_base => {
                base = registers[getRegisterId(.a, a_register)];
                if (base < 2) return error.BaseUndeflow;
            },
            .swap_stacks => {
                x_stack +%= 1;
            },
            .cycle_registers => {
                if (a_register == 0)
                    a_register = 2
                else
                    a_register -= 1;
            },
            .push_a => {
                try push(
                    stacks[x_stack],
                    registers[getRegisterId(.a, a_register)],
                );
            },
            .pop_a => {
                registers[getRegisterId(.a, a_register)] =
                    try pop(stacks[x_stack]);
            },
            .push_0 => {
                try push(
                    stacks[x_stack],
                    0,
                );
            },
            .push_1 => {
                try push(
                    stacks[x_stack],
                    1,
                );
            },
            .skip_block => {
                if (try checkLeq(
                    registers[getRegisterId(.a, a_register)],
                    registers[getRegisterId(.b, a_register)],
                    registers[getRegisterId(.c, a_register)],
                    base,
                )) {
                    var depth: usize = 1;
                    while (program_reader.readByte() catch null) |inner_byte| : ({
                        if (depth == 0) break;
                    }) {
                        if (inner_byte == @intFromEnum(Command.start_block)) {
                            depth += 1;
                        } else if (inner_byte == @intFromEnum(Command.end_block)) {
                            depth -= 1;
                        }
                    } else {
                        // reached end of file
                        if (depth - 1 != 0)
                            return error.UnclosedBlock
                        else
                            return;
                    }

                    try seekable_program.seekBy(-1); // go to the end_block
                }
            },
            .loop_block => {
                if (try checkGt(
                    registers[getRegisterId(.a, a_register)],
                    registers[getRegisterId(.b, a_register)],
                    registers[getRegisterId(.c, a_register)],
                    base,
                )) {
                    try seekable_program.seekTo(blocks.getLastOrNull() orelse 0);
                }
            },
            .start_block => {
                try blocks.append(try seekable_program.getPos());
            },
            .end_block => {
                _ = blocks.popOrNull() orelse
                    return error.UnopenedBlock;
            },
            .input => {
                var input_buffer = std.ArrayList(u8).init(allocator);
                defer input_buffer.deinit();
                try stdin.streamUntilDelimiter(input_buffer.writer(), '\n', null);

                try push(
                    stacks[x_stack],
                    try std.fmt.parseUnsigned(Nat, input_buffer.items, 10),
                );
            },
            .output => {
                try std.fmt.formatInt(
                    registers[getRegisterId(.a, a_register)],
                    10,
                    .lower,
                    .{},
                    stdout,
                );
                try stdout.writeByte('\n');
            },
            .comment => {
                while (program_reader.readByte() catch null) |inner_byte| {
                    if (inner_byte == '\n') break;
                }
            },
            _ => {
                if (!std.ascii.isWhitespace(byte))
                    return error.BadCommand;
            },
        }
    }
}

fn getRegisterId(register_id: RegisterId, a_id: u2) u2 {
    return @intCast((@as(u3, @intFromEnum(register_id)) + a_id) % 3);
}

fn push(stack: *std.ArrayList(Nat), value: Nat) !void {
    try stack.append(value);
}
fn pop(stack: *std.ArrayList(Nat)) !Nat {
    return stack.popOrNull() orelse
        return error.StackUnderflow;
}

fn dwNot(a: Nat, c: Nat, base: Nat) !Nat {
    var result: Nat = a;

    var index: Nat = 0;
    while (index < c) : (index += 1) {
        const current_digit = try getDigit(result, base, index);

        result = try setDigit(
            result,
            base,
            index,
            (base - 1) - current_digit,
        );
    }

    return result;
}

fn dwOr(a: Nat, b: Nat, c: Nat, base: Nat) !Nat {
    var result: Nat = a;

    var index: Nat = 0;
    while (index < c) : (index += 1) {
        const current_digit_a = try getDigit(a, base, index);
        const current_digit_b = try getDigit(b, base, index);

        result = try setDigit(
            result,
            base,
            index,
            @min(current_digit_a + current_digit_b, base - 1),
        );
    }

    return result;
}

fn dwXor(a: Nat, b: Nat, c: Nat, base: Nat) !Nat {
    var result: Nat = a;

    var index: Nat = 0;
    while (index < c) : (index += 1) {
        const current_digit_a = try getDigit(a, base, index);
        const current_digit_b = try getDigit(b, base, index);

        result = try setDigit(
            result,
            base,
            index,
            (current_digit_a + current_digit_b) % base,
        );
    }

    return result;
}

fn dwAnd(a: Nat, b: Nat, c: Nat, base: Nat) !Nat {
    var result: Nat = a;

    var index: Nat = 0;
    while (index < c) : (index += 1) {
        const current_digit_a = try getDigit(a, base, index);
        const current_digit_b = try getDigit(b, base, index);

        result = try setDigit(
            result,
            base,
            index,
            @min(current_digit_a * current_digit_b, base - 1),
        );
    }

    return result;
}

// modular and
fn dwMand(a: Nat, b: Nat, c: Nat, base: Nat) !Nat {
    var result: Nat = a;

    var index: Nat = 0;
    while (index < c) : (index += 1) {
        const current_digit_a = try getDigit(a, base, index);
        const current_digit_b = try getDigit(b, base, index);

        result = try setDigit(
            result,
            base,
            index,
            (current_digit_a * current_digit_b) % base,
        );
    }

    return result;
}

fn shiftLeft(a: Nat, b: Nat, base: Nat) !Nat {
    const shift_amount = try std.math.powi(Nat, base, b);
    return try std.math.mul(Nat, a, shift_amount);
}

fn shiftRight(a: Nat, b: Nat, base: Nat) !Nat {
    const shift_amount = try std.math.powi(Nat, base, b);
    return a / shift_amount;
}

fn digitCount(a: Nat, base: Nat) !Nat {
    if (a == 0)
        return 0;

    return std.math.log_int(Nat, base, a) + 1;
}

fn checkLeq(a: Nat, b: Nat, c: Nat, base: Nat) !bool {
    var index: Nat = 0;
    while (index < c) : (index += 1) {
        if (try getDigit(a, base, index) > try getDigit(b, base, index)) {
            return false;
        }
    }

    return true;
}
fn checkGt(a: Nat, b: Nat, c: Nat, base: Nat) !bool {
    if (c == 0) return false;

    var index: Nat = 0;
    while (index < c) : (index += 1) {
        if (try getDigit(a, base, index) <= try getDigit(b, base, index)) {
            return false;
        }
    }

    return true;
}

fn getDigit(
    value: Nat,
    base: Nat,
    index: Nat,
) !Nat {
    const place_value = try std.math.powi(Nat, base, index);
    const shifted_down = value / place_value;

    return shifted_down % base;
}

fn setDigit(
    value: Nat,
    base: Nat,
    index: Nat,
    new_digit: Nat,
) !Nat {
    if (new_digit >= base)
        return error.DigitTooLarge;

    const place_value = try std.math.powi(Nat, base, index);
    const old_digit = try getDigit(value, base, index);

    const shifted_old_digit = old_digit * place_value;
    const shifted_new_digit = new_digit * place_value;

    const value_without_digit = value - shifted_old_digit;

    const result = try std.math.add(Nat, value_without_digit, shifted_new_digit);

    return result;
}
