pub static mut ENDPOINTS: Endpoints = Endpoints{ dispatch: None, sdk: None};

pub struct Endpoints {
    pub dispatch: Option<String>,
    pub sdk: Option<String>,
}