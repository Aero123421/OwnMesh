//! Minimal i18n strings for OwnMesh TUI (en, ja, zh-Hans, ru).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Ja,
    ZhHans,
    Ru,
}

impl Lang {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "ja" | "ja-jp" | "jp" => Self::Ja,
            "zh" | "zh-cn" | "zh-hans" => Self::ZhHans,
            "ru" | "ru-ru" => Self::Ru,
            _ => Self::En,
        }
    }
}

#[allow(dead_code)]
pub struct Strings {
    pub app_title: &'static str,
    pub dashboard: &'static str,
    pub devices: &'static str,
    pub sessions: &'static str,
    pub approvals: &'static str,
    pub settings: &'static str,
    pub help: &'static str,
}

pub fn strings(lang: Lang) -> Strings {
    match lang {
        Lang::En => Strings {
            app_title: "OwnMesh",
            dashboard: "Dashboard",
            devices: "Devices",
            sessions: "Sessions",
            approvals: "Approvals",
            settings: "Settings",
            help: "Help (F1)",
        },
        Lang::Ja => Strings {
            app_title: "OwnMesh",
            dashboard: "ダッシュボード",
            devices: "デバイス",
            sessions: "セッション",
            approvals: "承認",
            settings: "設定",
            help: "ヘルプ (F1)",
        },
        Lang::ZhHans => Strings {
            app_title: "OwnMesh",
            dashboard: "仪表盘",
            devices: "设备",
            sessions: "会话",
            approvals: "审批",
            settings: "设置",
            help: "帮助 (F1)",
        },
        Lang::Ru => Strings {
            app_title: "OwnMesh",
            dashboard: "Панель",
            devices: "Устройства",
            sessions: "Сессии",
            approvals: "Одобрения",
            settings: "Настройки",
            help: "Справка (F1)",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_langs_have_title() {
        for lang in [Lang::En, Lang::Ja, Lang::ZhHans, Lang::Ru] {
            assert!(!strings(lang).app_title.is_empty());
            assert!(!strings(lang).dashboard.is_empty());
        }
    }
}
