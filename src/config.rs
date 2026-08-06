pub static mut ENDPOINTS: Endpoints = Endpoints{ dispatch: None, sdk: None};
pub static mut CONFIG: AppConfig = AppConfig{ usesRedirect: false, fileLogging: false};

pub struct Endpoints {
    pub dispatch: Option<String>,
    pub sdk: Option<String>,
}

pub struct AppConfig {
    pub usesRedirect: bool,
    pub fileLogging: bool,
}
