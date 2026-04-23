//! Localization — English/Russian

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Lang {
    En,
    Ru,
}

impl Lang {
    pub fn load() -> Self {
        let path = dirs::data_local_dir()
            .unwrap_or_default()
            .join("AIVPN")
            .join("lang.txt");
        if let Ok(v) = std::fs::read_to_string(&path) {
            match v.trim() {
                "ru" => return Lang::Ru,
                _ => return Lang::En,
            }
        }
        Lang::En
    }

    pub fn save(&self) {
        let path = dirs::data_local_dir()
            .unwrap_or_default()
            .join("AIVPN")
            .join("lang.txt");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(
            &path,
            match self {
                Lang::En => "en",
                Lang::Ru => "ru",
            },
        );
    }

    pub fn toggle(&mut self) {
        *self = match self {
            Lang::En => Lang::Ru,
            Lang::Ru => Lang::En,
        };
        self.save();
    }

    pub fn label(&self) -> &'static str {
        match self {
            Lang::En => "EN",
            Lang::Ru => "RU",
        }
    }
}

/// Translate a key to current language
pub fn t(lang: Lang, key: &str) -> &'static str {
    match (lang, key) {
        // Status
        (Lang::En, "status") => "Status",
        (Lang::Ru, "status") => "Статус",
        (Lang::En, "connected") => "Connected",
        (Lang::Ru, "connected") => "Подключено",
        (Lang::En, "disconnected") => "Disconnected",
        (Lang::Ru, "disconnected") => "Отключено",
        (Lang::En, "connecting") => "Connecting...",
        (Lang::Ru, "connecting") => "Подключение...",
        (Lang::En, "disconnecting") => "Disconnecting...",
        (Lang::Ru, "disconnecting") => "Отключение...",

        // Buttons
        (Lang::En, "connect") => "Connect",
        (Lang::Ru, "connect") => "Подключить",
        (Lang::En, "disconnect") => "Disconnect",
        (Lang::Ru, "disconnect") => "Отключить",

        // Keys
        (Lang::En, "keys") => "Connection Keys",
        (Lang::Ru, "keys") => "Ключи подключения",
        (Lang::En, "add_key") => "Add Key",
        (Lang::Ru, "add_key") => "Добавить ключ",
        (Lang::En, "key_name") => "Name",
        (Lang::Ru, "key_name") => "Название",
        (Lang::En, "key_value") => "Key (aivpn://...)",
        (Lang::Ru, "key_value") => "Ключ (aivpn://...)",
        (Lang::En, "save") => "Save",
        (Lang::Ru, "save") => "Сохранить",
        (Lang::En, "cancel") => "Cancel",
        (Lang::Ru, "cancel") => "Отмена",
        (Lang::En, "delete") => "Delete",
        (Lang::Ru, "delete") => "Удалить",
        (Lang::En, "edit") => "Edit",
        (Lang::Ru, "edit") => "Изм.",
        (Lang::En, "no_keys") => "No keys added",
        (Lang::Ru, "no_keys") => "Ключи не добавлены",

        // Traffic
        (Lang::En, "traffic") => "Traffic",
        (Lang::Ru, "traffic") => "Трафик",
        (Lang::En, "downloaded") => "Downloaded",
        (Lang::Ru, "downloaded") => "Получено",
        (Lang::En, "uploaded") => "Uploaded",
        (Lang::Ru, "uploaded") => "Отправлено",

        // Options
        (Lang::En, "full_tunnel") => "Route all traffic through VPN",
        (Lang::Ru, "full_tunnel") => "Весь трафик через VPN",

        // Misc
        (Lang::En, "quit") => "Quit",
        (Lang::Ru, "quit") => "Выход",
        (Lang::En, "version") => "Version",
        (Lang::Ru, "version") => "Версия",
        (Lang::En, "no_key_selected") => "Select a key first",
        (Lang::Ru, "no_key_selected") => "Сначала выберите ключ",
        (Lang::En, "client_not_found") => "Client binary not found",
        (Lang::Ru, "client_not_found") => "Клиент не найден",

        // Recording
        (Lang::En, "record_new_mask") => "Record New Mask",
        (Lang::Ru, "record_new_mask") => "Записать новую маску",
        (Lang::En, "record_service_name") => "Service name",
        (Lang::Ru, "record_service_name") => "Имя сервиса",
        (Lang::En, "stop_recording") => "Stop Recording",
        (Lang::Ru, "stop_recording") => "Остановить запись",
        (Lang::En, "recording_ready") => "Ready to record",
        (Lang::Ru, "recording_ready") => "Готово к записи",
        (Lang::En, "recording_starting") => "Starting recording...",
        (Lang::Ru, "recording_starting") => "Запуск записи...",
        (Lang::En, "recording_active") => "Recording in progress — use the service normally",
        (Lang::Ru, "recording_active") => "Запись идёт — используйте сервис",
        (Lang::En, "recording_stopping") => "Stopping recording...",
        (Lang::Ru, "recording_stopping") => "Остановка записи...",
        (Lang::En, "recording_analyzing") => "Server analyzing traffic...",
        (Lang::Ru, "recording_analyzing") => "Сервер анализирует трафик...",
        (Lang::En, "recording_success") => "Mask recorded",
        (Lang::Ru, "recording_success") => "Маска записана",
        (Lang::En, "recording_failed") => "Recording failed",
        (Lang::Ru, "recording_failed") => "Запись не удалась",
        (Lang::En, "recording_self_test_failed") => "Self-test failed",
        (Lang::Ru, "recording_self_test_failed") => "Самотест не пройден",
        (Lang::En, "dismiss") => "Dismiss",
        (Lang::Ru, "dismiss") => "Закрыть",

        // Default fallback
        (_, _) => "???"
    }
}
