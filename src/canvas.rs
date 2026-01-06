pub mod client;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Course {
    pub id: i64,
    pub name: String,
    pub sis_course_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub sis_user_id: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub login_id: Option<String>,
    pub email: Option<String>,
}
