use std::sync::Arc;
use tokio::sync::RwLock;

use crate::domain::UserStore;

#[derive(Clone)]
pub struct AppState<T> {
    pub user_store: Arc<RwLock<T>>,
}

impl<T: UserStore> AppState<T> {
    pub fn new(user_store: Arc<RwLock<T>>) -> Self {
        Self { user_store }
    }
}
