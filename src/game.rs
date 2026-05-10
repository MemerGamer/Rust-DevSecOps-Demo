#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Player {
    X,
    O,
}

impl Player {
    pub fn next(self) -> Self {
        match self {
            Player::X => Player::O,
            Player::O => Player::X,
        }
    }
}

impl std::fmt::Display for Player {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Player::X => write!(f, "X"),
            Player::O => write!(f, "O"),
        }
    }
}

#[derive(Default)]
pub struct Board {
    cells: [[Option<Player>; 3]; 3],
}

impl Board {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn display(&self) {
        for row in &self.cells {
            let row_str: Vec<&str> = row
                .iter()
                .map(|c| match c {
                    Some(Player::X) => "X",
                    Some(Player::O) => "O",
                    None => ".",
                })
                .collect();
            println!("{}", row_str.join("|"));
        }
        println!();
    }

    pub fn make_move(&mut self, row: usize, col: usize, player: Player) -> bool {
        if row >= 3 || col >= 3 || self.cells[row][col].is_some() {
            return false;
        }
        self.cells[row][col] = Some(player);
        true
    }

    pub fn check_winner(&self) -> Option<Player> {
        for row in &self.cells {
            if row[0].is_some() && row[0] == row[1] && row[1] == row[2] {
                return row[0];
            }
        }
        for col in 0..3 {
            if self.cells[0][col].is_some()
                && self.cells[0][col] == self.cells[1][col]
                && self.cells[1][col] == self.cells[2][col]
            {
                return self.cells[0][col];
            }
        }
        if self.cells[0][0].is_some()
            && self.cells[0][0] == self.cells[1][1]
            && self.cells[1][1] == self.cells[2][2]
        {
            return self.cells[0][0];
        }
        if self.cells[0][2].is_some()
            && self.cells[0][2] == self.cells[1][1]
            && self.cells[1][1] == self.cells[2][0]
        {
            return self.cells[0][2];
        }
        None
    }

    pub fn is_draw(&self) -> bool {
        self.check_winner().is_none()
            && self.cells.iter().all(|row| row.iter().all(|c| c.is_some()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_win_row() {
        let mut board = Board::new();
        board.make_move(0, 0, Player::X);
        board.make_move(0, 1, Player::X);
        board.make_move(0, 2, Player::X);
        assert_eq!(board.check_winner(), Some(Player::X));
    }

    #[test]
    fn test_win_col() {
        let mut board = Board::new();
        board.make_move(0, 0, Player::O);
        board.make_move(1, 0, Player::O);
        board.make_move(2, 0, Player::O);
        assert_eq!(board.check_winner(), Some(Player::O));
    }

    #[test]
    fn test_win_diagonal() {
        let mut board = Board::new();
        board.make_move(0, 0, Player::X);
        board.make_move(1, 1, Player::X);
        board.make_move(2, 2, Player::X);
        assert_eq!(board.check_winner(), Some(Player::X));
    }

    #[test]
    fn test_win_anti_diagonal() {
        let mut board = Board::new();
        board.make_move(0, 2, Player::O);
        board.make_move(1, 1, Player::O);
        board.make_move(2, 0, Player::O);
        assert_eq!(board.check_winner(), Some(Player::O));
    }

    #[test]
    fn test_draw() {
        let mut board = Board::new();
        // X O X
        // X X O
        // O X O  <- draw
        board.make_move(0, 0, Player::X);
        board.make_move(0, 1, Player::O);
        board.make_move(0, 2, Player::X);
        board.make_move(1, 0, Player::X);
        board.make_move(1, 1, Player::X);
        board.make_move(1, 2, Player::O);
        board.make_move(2, 0, Player::O);
        board.make_move(2, 1, Player::X);
        board.make_move(2, 2, Player::O);
        assert!(board.is_draw());
        assert!(board.check_winner().is_none());
    }

    #[test]
    fn test_invalid_move_occupied() {
        let mut board = Board::new();
        assert!(board.make_move(0, 0, Player::X));
        assert!(!board.make_move(0, 0, Player::O));
    }

    #[test]
    fn test_invalid_move_out_of_bounds() {
        let mut board = Board::new();
        assert!(!board.make_move(3, 0, Player::X));
        assert!(!board.make_move(0, 3, Player::X));
    }

    #[test]
    fn test_no_winner_empty_board() {
        let board = Board::new();
        assert!(board.check_winner().is_none());
        assert!(!board.is_draw());
    }

    #[test]
    fn test_player_next() {
        assert_eq!(Player::X.next(), Player::O);
        assert_eq!(Player::O.next(), Player::X);
    }
}
