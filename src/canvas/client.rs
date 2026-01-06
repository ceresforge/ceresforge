use super::{Course, User};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue};

pub struct Client {
    base_url: String,
    client: reqwest::Client,
}
impl Client {
    pub fn new(base_url: &str, token: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let mut val = HeaderValue::from_str(format!("Bearer {}", token).as_str()).unwrap();
        val.set_sensitive(true);
        headers.insert(AUTHORIZATION, val);
        Self {
            base_url: format!("{}/api/v1", base_url),
            client: reqwest::Client::builder()
                .default_headers(headers)
                .build()
                .unwrap(),
        }
    }

    pub fn from_env() -> Result<Self, std::env::VarError> {
        let base_url = std::env::var("CANVAS_BASE_URL")?;
        let token = std::env::var("CANVAS_TOKEN")?;
        Ok(Self::new(&base_url, &token))
    }

    fn parse_next_link(val: &str) -> Option<String> {
        val.split(',')
            .find(|part| part.contains("rel=\"next\""))
            .and_then(|part| {
                let start = part.find('<')? + 1;
                let end = part.find('>')?;
                Some(part[start..end].to_string())
            })
    }

    #[allow(dead_code)]
    pub async fn list_courses(&self) -> Result<Vec<Course>, reqwest::Error> {
        let url = format!("{}/courses?per_page=100", self.base_url);
        let courses = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<Course>>()
            .await?;
        Ok(courses)
    }

    #[allow(dead_code)]
    pub async fn list_students(&self, course_id: i64) -> Result<Vec<User>, reqwest::Error> {
        let mut students = Vec::new();
        let mut url = Some(format!(
            "{}/courses/{course_id}/users?enrollment_type[]=student&include[]=email&per_page=100",
            self.base_url
        ));
        while let Some(current_url) = url {
            let res = self
                .client
                .get(current_url)
                .send()
                .await?
                .error_for_status()?;
            url = res
                .headers()
                .get("link")
                .and_then(|h| h.to_str().ok())
                .and_then(Self::parse_next_link);
            let mut current_students = res.json::<Vec<User>>().await?;
            students.append(&mut current_students);
        }
        Ok(students)
    }

    #[allow(dead_code)]
    pub async fn list_tas(&self, course_id: i64) -> Result<Vec<User>, reqwest::Error> {
        let mut tas = Vec::new();
        let mut url = Some(format!(
            "{}/courses/{course_id}/users?enrollment_type[]=ta&include[]=email&per_page=100",
            self.base_url
        ));
        while let Some(current_url) = url {
            let res = self
                .client
                .get(current_url)
                .send()
                .await?
                .error_for_status()?;
            url = res
                .headers()
                .get("link")
                .and_then(|h| h.to_str().ok())
                .and_then(Self::parse_next_link);
            let mut current_tas = res.json::<Vec<User>>().await?;
            tas.append(&mut current_tas);
        }
        Ok(tas)
    }

    #[allow(dead_code)]
    pub async fn list_teachers(&self, course_id: i64) -> Result<Vec<User>, reqwest::Error> {
        let mut teachers = Vec::new();
        let mut url = Some(format!(
            "{}/courses/{course_id}/users?enrollment_type[]=teacher&include[]=email&per_page=100",
            self.base_url
        ));
        while let Some(current_url) = url {
            let res = self
                .client
                .get(current_url)
                .send()
                .await?
                .error_for_status()?;
            url = res
                .headers()
                .get("link")
                .and_then(|h| h.to_str().ok())
                .and_then(Self::parse_next_link);
            let mut current_teachers = res.json::<Vec<User>>().await?;
            teachers.append(&mut current_teachers);
        }
        Ok(teachers)
    }
}
