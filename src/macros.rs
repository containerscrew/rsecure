#[macro_export]
macro_rules! print_message {
    ($($arg:tt)*) => {
        println!("{}", format!($($arg)*).truecolor(255, 165, 0));
    }
}