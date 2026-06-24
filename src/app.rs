// app.rs — SecPass UI (egui/eframe)

use eframe::egui::{self, Color32, FontId, RichText, Stroke, Rounding, Vec2, Ui};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::password_gen::{generate, PasswordOptions};
use crate::totp;
use crate::vault::{Entry, Vault, MIN_MASTER_PASSWORD_CHARS};

// ── Palette ────────────────────────────────────────────────────────────────
const BG: Color32          = Color32::from_rgb(15, 15, 18);
const SURFACE: Color32     = Color32::from_rgb(22, 22, 28);
const SURFACE2: Color32    = Color32::from_rgb(30, 30, 38);
const ACCENT: Color32      = Color32::from_rgb(91, 141, 184);
const ACCENT_DIM: Color32  = Color32::from_rgb(55, 90, 120);
const TEXT: Color32        = Color32::from_rgb(220, 220, 230);
const TEXT_DIM: Color32    = Color32::from_rgb(130, 130, 145);
const DANGER: Color32      = Color32::from_rgb(200, 70, 70);
const SUCCESS: Color32     = Color32::from_rgb(70, 170, 100);
const BORDER: Color32      = Color32::from_rgb(45, 45, 58);

const NEW_ENTRY_ID: &str = "new";
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
const AUTO_LOCK_AFTER: Duration = Duration::from_secs(5 * 60);

// ── Screen states ───────────────────────────────────────────────────────────
#[derive(PartialEq)]
enum Screen {
    Welcome,      // First launch: create or open vault
    Unlock,       // Vault selected, enter password
    Vault,        // Main vault view
}

#[derive(PartialEq)]
enum Modal {
    None,
    ViewEntry(String),    // entry id
    EditEntry(String),    // entry id (or "new")
    DeleteConfirm(String),
    ChangePassword,
    GeneratePassword(String), // return-to edit modal id, usually "new" or entry id
}

pub struct SecPassApp {
    screen: Screen,
    modal: Modal,

    // Welcome/unlock state
    pending_path: Option<PathBuf>,
    password_input: String,
    confirm_password_input: String,
    error_message: Option<String>,
    is_creating: bool, // true = creating new vault, false = opening existing

    // Vault state
    vault: Option<Vault>,
    search_query: String,
    status_message: Option<(String, bool)>, // (message, is_error)

    // Entry edit buffer
    edit_buffer: Entry,
    show_password: bool,

    // Password generator state
    gen_opts: PasswordOptions,
    gen_preview: String,

    // Change password
    new_password_input: String,
    new_password_confirm: String,

    // Clipboard clear timer
    clipboard_clear_at: Option<Instant>,
    last_activity_at: Instant,
}

#[derive(Clone)]
struct EntryListItem {
    id: String,
    title: String,
    username: String,
    has_totp: bool,
}

impl Default for SecPassApp {
    fn default() -> Self {
        let gen_opts = PasswordOptions::default();
        let gen_preview = generate(&gen_opts);
        Self {
            screen: Screen::Welcome,
            modal: Modal::None,
            pending_path: None,
            password_input: String::new(),
            confirm_password_input: String::new(),
            error_message: None,
            is_creating: false,
            vault: None,
            search_query: String::new(),
            status_message: None,
            edit_buffer: Entry::new(),
            show_password: false,
            gen_opts,
            gen_preview,
            new_password_input: String::new(),
            new_password_confirm: String::new(),
            clipboard_clear_at: None,
            last_activity_at: Instant::now(),
        }
    }
}

impl SecPassApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_visuals(&cc.egui_ctx);
        Self::default()
    }

    fn copy_to_clipboard(&mut self, text: &str, ctx: &egui::Context, label: &str) {
        ctx.output_mut(|o| o.copied_text = text.to_string());
        self.clipboard_clear_at = Some(Instant::now() + CLIPBOARD_CLEAR_AFTER);
        self.set_status(&format!("{} copied — clipboard clears in 30 seconds", label), false);
    }

    fn clear_clipboard(&mut self, ctx: &egui::Context) {
        ctx.output_mut(|o| o.copied_text = String::new());
        self.clipboard_clear_at = None;
    }

    fn set_status(&mut self, msg: &str, is_error: bool) {
        self.status_message = Some((msg.to_string(), is_error));
    }

    fn clear_unlock_inputs(&mut self) {
        self.password_input.zeroize();
        self.confirm_password_input.zeroize();
    }

    fn clear_change_password_inputs(&mut self) {
        self.new_password_input.zeroize();
        self.new_password_confirm.zeroize();
    }

    fn lock_vault(&mut self, ctx: Option<&egui::Context>) {
        if let Some(ref mut vault) = self.vault {
            if vault.is_modified {
                let _ = vault.save();
            }
        }
        self.vault = None;
        self.modal = Modal::None;
        self.edit_buffer = Entry::new();
        self.show_password = false;
        self.search_query.clear();
        self.clear_unlock_inputs();
        self.clear_change_password_inputs();
        if let Some(ctx) = ctx {
            self.clear_clipboard(ctx);
        }
        self.status_message = None;
        self.screen = if self.pending_path.is_some() { Screen::Unlock } else { Screen::Welcome };
    }

    fn note_activity(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| !i.events.is_empty()) {
            self.last_activity_at = Instant::now();
        }
    }

    fn master_password_error(password: &str) -> Option<String> {
        if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
            Some(format!(
                "Master password must be at least {} characters. Prefer a 4–6 word passphrase.",
                MIN_MASTER_PASSWORD_CHARS
            ))
        } else {
            None
        }
    }

    fn save_vault(&mut self) {
        if let Some(ref mut vault) = self.vault {
            match vault.save() {
                Ok(_) => self.set_status("Vault saved.", false),
                Err(e) => self.set_status(&format!("Save failed: {}", e), true),
            }
        }
    }

    // ── Screens ──────────────────────────────────────────────────────────────

    fn show_welcome(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);

            // Lock icon (SVG-style drawn with egui shapes)
            draw_lock_icon(ui);

            ui.add_space(24.0);
            ui.label(RichText::new("SecPass").font(FontId::proportional(36.0)).color(TEXT).strong());
            ui.add_space(4.0);
            ui.label(RichText::new("Your vault. Your keys. No cloud.").color(TEXT_DIM).size(14.0));
            ui.add_space(48.0);

            let btn_size = Vec2::new(220.0, 44.0);

            if styled_button(ui, "Create New Vault", btn_size, true) {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Create SecPass Vault")
                    .add_filter("SecPass Vault", &["secpass"])
                    .set_file_name("my-vault.secpass")
                    .save_file()
                {
                    self.pending_path = Some(path);
                    self.is_creating = true;
                    self.clear_unlock_inputs();
                    self.error_message = None;
                    self.screen = Screen::Unlock;
                }
            }

            ui.add_space(12.0);

            if styled_button(ui, "Open Existing Vault", btn_size, false) {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Open SecPass Vault")
                    .add_filter("SecPass Vault", &["secpass"])
                    .pick_file()
                {
                    self.pending_path = Some(path);
                    self.is_creating = false;
                    self.clear_unlock_inputs();
                    self.error_message = None;
                    self.screen = Screen::Unlock;
                }
            }
        });
    }

    fn show_unlock(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);

            draw_lock_icon(ui);
            ui.add_space(20.0);

            let title = if self.is_creating { "Create Vault" } else { "Unlock Vault" };
            ui.label(RichText::new(title).font(FontId::proportional(28.0)).color(TEXT).strong());

            if let Some(ref path) = self.pending_path.clone() {
                ui.add_space(6.0);
                let name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("vault.secpass");
                ui.label(RichText::new(name).color(TEXT_DIM).size(12.0).monospace());
            }

            ui.add_space(32.0);

            // Password field
            let pw_field = egui::TextEdit::singleline(&mut self.password_input)
                .password(true)
                .hint_text("Master password")
                .desired_width(280.0)
                .font(FontId::monospace(14.0));
            let resp = ui.add(pw_field);

            // If creating, show confirm field
            if self.is_creating {
                ui.add_space(10.0);
                let confirm_field = egui::TextEdit::singleline(&mut self.confirm_password_input)
                    .password(true)
                    .hint_text("Confirm master password")
                    .desired_width(280.0)
                    .font(FontId::monospace(14.0));
                ui.add(confirm_field);
            }

            ui.add_space(8.0);

            if let Some(ref err) = self.error_message.clone() {
                ui.label(RichText::new(err).color(DANGER).size(13.0));
                ui.add_space(4.0);
            }

            let btn_label = if self.is_creating { "Create Vault" } else { "Unlock" };
            let enter_pressed = ui.input(|i| i.key_pressed(egui::Key::Enter));

            if styled_button(ui, btn_label, Vec2::new(220.0, 44.0), true) || enter_pressed {
                self.try_unlock();
            }

            ui.add_space(16.0);

            if styled_button(ui, "← Back", Vec2::new(120.0, 36.0), false) {
                self.screen = Screen::Welcome;
                self.clear_unlock_inputs();
                self.error_message = None;
            }
        });
    }

    fn try_unlock(&mut self) {
        let path = match self.pending_path.clone() {
            Some(p) => p,
            None => return,
        };

        if self.password_input.is_empty() {
            self.error_message = Some("Password cannot be empty.".into());
            return;
        }

        if self.is_creating {
            if let Some(msg) = Self::master_password_error(&self.password_input) {
                self.error_message = Some(msg);
                return;
            }
            if self.password_input != self.confirm_password_input {
                self.error_message = Some("Passwords do not match.".into());
                return;
            }

            let password = std::mem::take(&mut self.password_input);
            self.confirm_password_input.zeroize();

            match Vault::create(path, password) {
                Ok(vault) => {
                    self.vault = Some(vault);
                    self.screen = Screen::Vault;
                    self.error_message = None;
                    self.last_activity_at = Instant::now();
                }
                Err(e) => {
                    self.error_message = Some(e.to_string());
                }
            }
        } else {
            let password = std::mem::take(&mut self.password_input);
            match Vault::open(path, password) {
                Ok(vault) => {
                    self.vault = Some(vault);
                    self.screen = Screen::Vault;
                    self.error_message = None;
                    self.last_activity_at = Instant::now();
                }
                Err(e) => {
                    self.error_message = Some(e.to_string());
                }
            }
        }
    }

    fn show_vault(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        // Top bar
        egui::TopBottomPanel::top("topbar")
            .frame(egui::Frame::none().fill(SURFACE).inner_margin(egui::Margin::symmetric(16.0, 10.0)))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("SecPass").color(ACCENT).strong().size(16.0));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if icon_button(ui, "⚙", "Settings") {
                            self.modal = Modal::ChangePassword;
                            self.clear_change_password_inputs();
                        }
                        if icon_button(ui, "🔒", "Lock vault") {
                            self.lock_vault(Some(ctx));
                        }
                        if icon_button(ui, "💾", "Save vault") {
                            self.save_vault();
                        }
                        // Status message
                        if let Some((ref msg, is_error)) = self.status_message.clone() {
                            let color = if is_error { DANGER } else { TEXT_DIM };
                            ui.label(RichText::new(msg).color(color).size(12.0));
                        }
                    });
                });
            });

        // Search bar + Add button
        egui::TopBottomPanel::top("searchbar")
            .frame(egui::Frame::none().fill(BG).inner_margin(egui::Margin::symmetric(16.0, 10.0)))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🔍").size(16.0));
                    let search = egui::TextEdit::singleline(&mut self.search_query)
                        .hint_text("Search entries…")
                        .desired_width(ui.available_width() - 120.0)
                        .font(FontId::proportional(14.0));
                    ui.add(search);

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if styled_button(ui, "+ New", Vec2::new(80.0, 32.0), true) {
                            self.edit_buffer = Entry::new();
                            self.show_password = false;
                            self.modal = Modal::EditEntry(NEW_ENTRY_ID.into());
                        }
                    });
                });
            });

        // Entry list. Build lightweight row summaries only; do not clone passwords/TOTP secrets for list rendering.
        let query = self.search_query.clone();
        let entries: Vec<EntryListItem> = self.vault.as_ref()
            .map(|v| {
                v.search(&query)
                    .into_iter()
                    .map(|e| EntryListItem {
                        id: e.id.clone(),
                        title: e.title.clone(),
                        username: e.username.clone(),
                        has_totp: e.totp_secret.is_some(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        if entries.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.label(RichText::new(
                    if self.vault.as_ref().map(|v| v.data.entries.is_empty()).unwrap_or(true) {
                        "Your vault is empty.\nClick '+ New' to add your first entry."
                    } else {
                        "No entries match your search."
                    }
                ).color(TEXT_DIM).size(14.0));
            });
        } else {
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add_space(4.0);
                for entry in &entries {
                    self.show_entry_row(ui, entry);
                }
                ui.add_space(8.0);
            });
        }
    }

    fn show_entry_row(&mut self, ui: &mut Ui, entry: &EntryListItem) {
        let id = entry.id.clone();
        let title = if entry.title.is_empty() { "(Untitled)" } else { &entry.title };
        let username = entry.username.clone();
        let has_totp = entry.has_totp;

        let row = egui::Frame::none()
            .fill(SURFACE)
            .rounding(Rounding::same(6.0))
            .stroke(Stroke::new(1.0, BORDER))
            .inner_margin(egui::Margin::symmetric(14.0, 10.0));

        row.show(ui, |ui| {
            ui.horizontal(|ui| {
                // Icon
                ui.label(RichText::new("🔑").size(18.0));
                ui.add_space(8.0);

                // Title + username
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).color(TEXT).strong().size(14.0));
                    if !username.is_empty() {
                        ui.label(RichText::new(&username).color(TEXT_DIM).size(12.0).monospace());
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if icon_button(ui, "🗑", "Delete") {
                        self.modal = Modal::DeleteConfirm(id.clone());
                    }
                    if icon_button(ui, "✏", "Edit") {
                        if let Some(ref vault) = self.vault {
                            if let Some(e) = vault.data.entries.iter().find(|e| e.id == id) {
                                self.edit_buffer = e.clone();
                                self.show_password = false;
                                self.modal = Modal::EditEntry(id.clone());
                            }
                        }
                    }
                    if icon_button(ui, "👁", "View") {
                        self.modal = Modal::ViewEntry(id.clone());
                    }
                    if has_totp {
                        ui.label(RichText::new("2FA").color(ACCENT).size(11.0).strong());
                    }
                });
            });
        });

        ui.add_space(4.0);
    }

    // ── Modals ────────────────────────────────────────────────────────────────

    fn show_modal(&mut self, ctx: &egui::Context) {
        match &self.modal {
            Modal::None => {}
            Modal::ViewEntry(id) => {
                let id = id.clone();
                self.show_view_modal(ctx, &id);
            }
            Modal::EditEntry(id) => {
                let id = id.clone();
                self.show_edit_modal(ctx, &id);
            }
            Modal::DeleteConfirm(id) => {
                let id = id.clone();
                self.show_delete_modal(ctx, &id);
            }
            Modal::ChangePassword => {
                self.show_change_password_modal(ctx);
            }
            Modal::GeneratePassword(return_to) => {
                let return_to = return_to.clone();
                self.show_gen_modal(ctx, &return_to);
            }
        }
    }

    fn show_view_modal(&mut self, ctx: &egui::Context, entry_id: &str) {
        let entry = self.vault.as_ref()
            .and_then(|v| v.data.entries.iter().find(|e| e.id == entry_id))
            .cloned();

        let Some(entry) = entry else {
            self.modal = Modal::None;
            return;
        };

        let mut open = true;
        egui::Window::new(if entry.title.is_empty() { "Entry" } else { &entry.title })
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .min_width(400.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(modal_frame())
            .show(ctx, |ui| {
                ui.set_width(400.0);

                detail_row(ui, "Username", &entry.username, true, || {
                    self.copy_to_clipboard(&entry.username, ctx, "Username");
                });

                detail_row(ui, "Password", &mask_password(&entry.password), true, || {
                    self.copy_to_clipboard(&entry.password, ctx, "Password");
                });

                if !entry.url.is_empty() {
                    detail_row(ui, "URL", &entry.url, false, || {});
                }

                if !entry.notes.is_empty() {
                    ui.add_space(6.0);
                    ui.label(RichText::new("Notes").color(TEXT_DIM).size(11.0));
                    ui.label(RichText::new(&entry.notes).color(TEXT).size(13.0));
                }

                // TOTP section
                if let Some(ref secret) = entry.totp_secret.clone() {
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(6.0);

                    ui.horizontal(|ui| {
                        ui.label(RichText::new("2FA Code").color(TEXT_DIM).size(11.0));

                        let secs = totp::seconds_remaining();
                        let color = if secs <= 5 { DANGER } else if secs <= 10 { Color32::YELLOW } else { SUCCESS };
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(RichText::new(format!("{}s", secs)).color(color).size(11.0).monospace());
                        });
                    });

                    match totp::generate_code(secret) {
                        Ok(code) => {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(&code)
                                        .font(FontId::monospace(28.0))
                                        .color(ACCENT)
                                        .strong()
                                );
                                ui.add_space(8.0);
                                if icon_button(ui, "📋", "Copy code") {
                                    self.copy_to_clipboard(&code, ctx, "TOTP code");
                                }
                            });
                        }
                        Err(e) => {
                            ui.label(RichText::new(format!("Error: {}", e)).color(DANGER).size(13.0));
                        }
                    }

                    // Request repaint to update the countdown
                    ctx.request_repaint_after(std::time::Duration::from_secs(1));
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if styled_button(ui, "Edit", Vec2::new(80.0, 32.0), true) {
                        self.edit_buffer = entry.clone();
                        self.show_password = false;
                        self.modal = Modal::EditEntry(entry.id.clone());
                    }
                    if styled_button(ui, "Close", Vec2::new(80.0, 32.0), false) {
                        self.modal = Modal::None;
                    }
                });
            });

        if !open {
            self.modal = Modal::None;
        }
    }

    fn show_edit_modal(&mut self, ctx: &egui::Context, entry_id: &str) {
        let is_new = entry_id == NEW_ENTRY_ID;
        let title = if is_new { "New Entry" } else { "Edit Entry" };
        let mut open = true;

        egui::Window::new(title)
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .min_width(420.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(modal_frame())
            .show(ctx, |ui| {
                ui.set_width(420.0);

                field_label(ui, "Title");
                ui.add(egui::TextEdit::singleline(&mut self.edit_buffer.title)
                    .desired_width(f32::INFINITY));
                ui.add_space(8.0);

                field_label(ui, "Username");
                ui.add(egui::TextEdit::singleline(&mut self.edit_buffer.username)
                    .desired_width(f32::INFINITY));
                ui.add_space(8.0);

                field_label(ui, "Password");
                ui.horizontal(|ui| {
                    let pw_edit = egui::TextEdit::singleline(&mut self.edit_buffer.password)
                        .password(!self.show_password)
                        .font(FontId::monospace(13.0))
                        .desired_width(ui.available_width() - 90.0);
                    ui.add(pw_edit);
                    if icon_button(ui, if self.show_password { "🙈" } else { "👁" }, "Show/hide") {
                        self.show_password = !self.show_password;
                    }
                    if icon_button(ui, "⚡", "Generate password") {
                        self.gen_preview = generate(&self.gen_opts);
                        self.modal = Modal::GeneratePassword(entry_id.to_string());
                    }
                });
                ui.add_space(8.0);

                field_label(ui, "URL");
                ui.add(egui::TextEdit::singleline(&mut self.edit_buffer.url)
                    .desired_width(f32::INFINITY));
                ui.add_space(8.0);

                field_label(ui, "Notes");
                ui.add(egui::TextEdit::multiline(&mut self.edit_buffer.notes)
                    .desired_width(f32::INFINITY)
                    .desired_rows(3));
                ui.add_space(8.0);

                // TOTP
                field_label(ui, "TOTP Secret (optional)");
                let mut totp_val = self.edit_buffer.totp_secret.clone().unwrap_or_default();
                let totp_edit = egui::TextEdit::singleline(&mut totp_val)
                    .hint_text("Base32 secret (e.g. JBSWY3DPEHPK3PXP)")
                    .font(FontId::monospace(13.0))
                    .desired_width(f32::INFINITY);
                if ui.add(totp_edit).changed() {
                    self.edit_buffer.totp_secret = if totp_val.is_empty() { None } else { Some(totp_val.clone()) };
                }
                if !totp_val.is_empty() {
                    if totp::validate_secret(&totp_val) {
                        ui.label(RichText::new("✓ Valid TOTP secret").color(SUCCESS).size(11.0));
                    } else {
                        ui.label(RichText::new("⚠ Invalid/too-short TOTP secret").color(DANGER).size(11.0));
                    }
                }

                ui.add_space(16.0);

                ui.horizontal(|ui| {
                    let save_label = if is_new { "Add Entry" } else { "Save Changes" };
                    if styled_button(ui, save_label, Vec2::new(120.0, 36.0), true) {
                        let mut entry = self.edit_buffer.clone();

                        if let Some(secret) = entry.totp_secret.clone() {
                            if secret.trim().is_empty() {
                                entry.totp_secret = None;
                            } else if let Some(normalized) = totp::normalize_secret(&secret) {
                                entry.totp_secret = Some(normalized);
                            } else {
                                self.set_status("Invalid TOTP secret — entry not saved.", true);
                                return;
                            }
                        }

                        entry.touch();
                        if is_new {
                            if let Some(ref mut vault) = self.vault {
                                vault.add_entry(entry);
                            }
                        } else {
                            if let Some(ref mut vault) = self.vault {
                                vault.update_entry(entry);
                            }
                        }
                        self.save_vault();
                        self.edit_buffer = Entry::new();
                        self.modal = Modal::None;
                    }
                    if styled_button(ui, "Cancel", Vec2::new(80.0, 36.0), false) {
                        self.edit_buffer = Entry::new();
                        self.modal = Modal::None;
                    }
                });
            });

        if !open {
            self.edit_buffer = Entry::new();
            self.modal = Modal::None;
        }
    }

    fn show_delete_modal(&mut self, ctx: &egui::Context, entry_id: &str) {
        let entry_title = self.vault.as_ref()
            .and_then(|v| v.data.entries.iter().find(|e| e.id == entry_id))
            .map(|e| if e.title.is_empty() { "(Untitled)".to_string() } else { e.title.clone() })
            .unwrap_or_default();

        let id = entry_id.to_string();
        let mut open = true;

        egui::Window::new("Delete Entry")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .min_width(320.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(modal_frame())
            .show(ctx, |ui| {
                ui.set_width(320.0);
                ui.label(RichText::new(format!(
                    "Delete \"{}\"? This cannot be undone.", entry_title
                )).color(TEXT).size(14.0));
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    if styled_button(ui, "Delete", Vec2::new(90.0, 36.0), true) {
                        if let Some(ref mut vault) = self.vault {
                            vault.delete_entry(&id);
                        }
                        self.save_vault();
                        self.modal = Modal::None;
                    }
                    if styled_button(ui, "Cancel", Vec2::new(90.0, 36.0), false) {
                        self.modal = Modal::None;
                    }
                });
            });

        if !open {
            self.modal = Modal::None;
        }
    }

    fn show_change_password_modal(&mut self, ctx: &egui::Context) {
        let mut open = true;

        egui::Window::new("Change Master Password")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .min_width(360.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(modal_frame())
            .show(ctx, |ui| {
                ui.set_width(360.0);

                field_label(ui, "New Password");
                ui.add(egui::TextEdit::singleline(&mut self.new_password_input)
                    .password(true)
                    .desired_width(f32::INFINITY));
                ui.add_space(8.0);

                field_label(ui, "Confirm New Password");
                ui.add(egui::TextEdit::singleline(&mut self.new_password_confirm)
                    .password(true)
                    .desired_width(f32::INFINITY));
                ui.add_space(16.0);

                ui.horizontal(|ui| {
                    if styled_button(ui, "Change Password", Vec2::new(150.0, 36.0), true) {
                        if let Some(msg) = Self::master_password_error(&self.new_password_input) {
                            self.set_status(&msg, true);
                        } else if self.new_password_input != self.new_password_confirm {
                            self.set_status("Passwords do not match.", true);
                        } else {
                            let new_pw = std::mem::take(&mut self.new_password_input);
                            self.new_password_confirm.zeroize();
                            if let Some(ref mut vault) = self.vault {
                                match vault.change_password(new_pw) {
                                    Ok(_) => {
                                        self.set_status("Master password changed.", false);
                                        self.clear_change_password_inputs();
                                        self.modal = Modal::None;
                                    }
                                    Err(e) => self.set_status(&e.to_string(), true),
                                }
                            }
                        }
                    }
                    if styled_button(ui, "Cancel", Vec2::new(80.0, 36.0), false) {
                        self.clear_change_password_inputs();
                        self.modal = Modal::None;
                    }
                });
            });

        if !open {
            self.clear_change_password_inputs();
            self.modal = Modal::None;
        }
    }

    fn show_gen_modal(&mut self, ctx: &egui::Context, return_to: &str) {
        let mut open = true;

        egui::Window::new("Generate Password")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .min_width(360.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(modal_frame())
            .show(ctx, |ui| {
                ui.set_width(360.0);

                // Preview
                ui.label(
                    RichText::new(&self.gen_preview)
                        .font(FontId::monospace(16.0))
                        .color(ACCENT)
                );
                ui.add_space(12.0);

                // Length slider
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Length").color(TEXT_DIM).size(13.0));
                    ui.add(egui::Slider::new(&mut self.gen_opts.length, 8..=64));
                });

                ui.checkbox(&mut self.gen_opts.use_uppercase, RichText::new("Uppercase (A-Z)").color(TEXT).size(13.0));
                ui.checkbox(&mut self.gen_opts.use_digits, RichText::new("Digits (0-9)").color(TEXT).size(13.0));
                ui.checkbox(&mut self.gen_opts.use_symbols, RichText::new("Symbols (!@#…)").color(TEXT).size(13.0));

                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    if styled_button(ui, "Regenerate", Vec2::new(120.0, 36.0), false) {
                        self.gen_preview = generate(&self.gen_opts);
                    }
                    if styled_button(ui, "Use This", Vec2::new(100.0, 36.0), true) {
                        self.edit_buffer.password.zeroize();
                        self.edit_buffer.password = self.gen_preview.clone();
                        self.modal = Modal::EditEntry(return_to.to_string());
                    }
                });
            });

        if !open {
            // Return to edit modal
            self.modal = Modal::EditEntry(return_to.to_string());
        }
    }
}

// ── eframe App impl ───────────────────────────────────────────────────────────

impl eframe::App for SecPassApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.note_activity(ctx);

        if self.screen == Screen::Vault && self.last_activity_at.elapsed() >= AUTO_LOCK_AFTER {
            self.lock_vault(Some(ctx));
            self.error_message = Some("Vault auto-locked after inactivity.".into());
        }

        // Clipboard auto-clear. This is best-effort; OS clipboard history or third-party
        // clipboard managers may keep their own copies.
        if let Some(clear_at) = self.clipboard_clear_at {
            if Instant::now() >= clear_at {
                self.clear_clipboard(ctx);
            } else {
                ctx.request_repaint_after(Duration::from_secs(1));
            }
        }

        // Main panel
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(BG))
            .show(ctx, |ui| {
                match self.screen {
                    Screen::Welcome => self.show_welcome(ui, ctx),
                    Screen::Unlock  => self.show_unlock(ui, ctx),
                    Screen::Vault   => self.show_vault(ui, ctx),
                }
            });

        // Modals rendered on top
        self.show_modal(ctx);
    }
}

// ── Visual helpers ────────────────────────────────────────────────────────────

fn setup_visuals(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.window_fill = SURFACE;
    visuals.panel_fill = BG;
    visuals.override_text_color = Some(TEXT);
    visuals.selection.bg_fill = ACCENT_DIM;
    visuals.widgets.noninteractive.bg_fill = SURFACE;
    visuals.widgets.inactive.bg_fill = SURFACE2;
    visuals.widgets.hovered.bg_fill = SURFACE2;
    visuals.widgets.active.bg_fill = ACCENT_DIM;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_DIM);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.extreme_bg_color = BG;
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(12.0, 6.0);
    ctx.set_style(style);
}

fn modal_frame() -> egui::Frame {
    egui::Frame::window(&egui::Style::default())
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .rounding(Rounding::same(8.0))
        .inner_margin(egui::Margin::same(20.0))
}

fn styled_button(ui: &mut Ui, label: &str, size: Vec2, primary: bool) -> bool {
    let (fill, text_color) = if primary {
        (ACCENT, Color32::WHITE)
    } else {
        (SURFACE2, TEXT)
    };

    let btn = egui::Button::new(RichText::new(label).color(text_color).size(13.0))
        .fill(fill)
        .rounding(Rounding::same(6.0))
        .min_size(size);

    ui.add(btn).clicked()
}

fn icon_button(ui: &mut Ui, icon: &str, tooltip: &str) -> bool {
    let resp = ui.add(
        egui::Button::new(RichText::new(icon).size(16.0))
            .fill(Color32::TRANSPARENT)
            .frame(false)
    );
    if !tooltip.is_empty() {
        resp.clone().on_hover_text(tooltip);
    }
    resp.clicked()
}

fn field_label(ui: &mut Ui, label: &str) {
    ui.label(RichText::new(label).color(TEXT_DIM).size(11.0));
}

fn detail_row(ui: &mut Ui, label: &str, value: &str, copyable: bool, on_copy: impl FnOnce()) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(label).color(TEXT_DIM).size(11.0));
            ui.label(RichText::new(value).color(TEXT).size(13.0).monospace());
        });
        if copyable {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if icon_button(ui, "📋", "Copy") {
                    on_copy();
                }
            });
        }
    });
    ui.add_space(6.0);
}

fn mask_password(pw: &str) -> String {
    "•".repeat(pw.len().min(24))
}

fn draw_lock_icon(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(56.0, 64.0), egui::Sense::hover());
    let painter = ui.painter();
    let center = rect.center();

    // Shackle (arc)
    painter.circle_stroke(
        egui::pos2(center.x, center.y - 14.0),
        14.0,
        Stroke::new(4.0, ACCENT),
    );

    // Body
    let body = egui::Rect::from_center_size(
        egui::pos2(center.x, center.y + 16.0),
        Vec2::new(36.0, 28.0),
    );
    painter.rect_filled(body, Rounding::same(5.0), ACCENT_DIM);
    painter.rect_stroke(body, Rounding::same(5.0), Stroke::new(2.0, ACCENT));

    // Keyhole
    painter.circle_filled(egui::pos2(center.x, center.y + 14.0), 5.0, BG);
}
