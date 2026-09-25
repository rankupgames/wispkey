#[tokio::main]
async fn main() {
    if std::env::args_os().len() != 1 {
        std::process::exit(2);
    }
    std::process::exit(wispkey::run_operation_helper().await);
}
