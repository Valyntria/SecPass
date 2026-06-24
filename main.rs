mod app;
mod crypto;
mod password_gen;
mod totp;
mod vault;

use app::SecPassApp;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "SecPass",
        options,
        Box::new(|cc| Box::new(SecPassApp::new(cc))),
    )
}
