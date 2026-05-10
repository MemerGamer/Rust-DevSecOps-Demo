mod game;
mod stats;

use std::io::{self, BufRead};

use game::{Board, Player};

fn main() {
    let stdin = io::stdin();
    let mut board = Board::new();
    let mut current = Player::X;

    println!("Tic Tac Toe");
    println!("Enter moves as: row,col (0-2 each)");
    println!();

    loop {
        board.display();
        println!("Player {}'s turn:", current);

        let line = stdin
            .lock()
            .lines()
            .next()
            .unwrap_or(Ok(String::new()))
            .unwrap_or_default();

        let parts: Vec<usize> = line
            .trim()
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();

        if parts.len() != 2 {
            println!("Invalid input. Use format: row,col");
            continue;
        }

        if !board.make_move(parts[0], parts[1], current) {
            println!("Invalid move. Try again.");
            continue;
        }

        if let Some(winner) = board.check_winner() {
            board.display();
            println!("Player {} wins!", winner);
            stats::log_result(&format!("{winner} wins"));
            break;
        }

        if board.is_draw() {
            board.display();
            println!("It's a draw!");
            stats::log_result("draw");
            break;
        }

        current = current.next();
    }
}
