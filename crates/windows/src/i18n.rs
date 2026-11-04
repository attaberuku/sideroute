//! English or Turkish user-interface text, following the Windows display language.

use std::sync::OnceLock;

use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;

fn turkish() -> bool {
    static T: OnceLock<bool> = OnceLock::new();
    *T.get_or_init(|| unsafe { GetUserDefaultUILanguage() } & 0x3ff == 0x1f) // LANG_TURKISH
}

/// Picks the text for the current language.
pub fn t(en: &'static str, tr: &'static str) -> &'static str {
    if turkish() { tr } else { en }
}

/// Like `t`, with `{}` replaced by `arg`.
pub fn t1(en: &'static str, tr: &'static str, arg: &str) -> String {
    t(en, tr).replace("{}", arg)
}
