use crate::doctor;

use super::shared::{json_output, print_json};

pub async fn handle_doctor() {
    let report = doctor::run_doctor().await;
    if json_output() {
        print_json(report.to_json());
    } else {
        println!("{}", doctor::render_text(&report));
    }
    if !report.ok {
        std::process::exit(1);
    }
}
