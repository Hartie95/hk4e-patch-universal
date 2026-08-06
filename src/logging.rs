use crate::{util, LOG_LEVEL};

pub unsafe fn setup_logging() {
    tracing_subscriber::fmt()
        .with_ansi(!util::is_wine())
        .with_max_level(LOG_LEVEL)
        .with_target(false)
        .init();
}
