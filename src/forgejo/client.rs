use std::collections::HashMap;

use crate::forgejo::{Organization, Permission, Team};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Serialize;

pub struct Client {
    base_url: String,
    client: reqwest::Client,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum CreateTeamPermission {
    Read,
    Write,
    Admin,
}

#[derive(Debug, Default, Serialize)]
pub struct CreateTeamOption {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_create_org_repo: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub includes_all_repositories: Option<bool>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<CreateTeamPermission>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units_map: Option<HashMap<String, Permission>>,
}

impl Client {
    pub fn new(base_url: &str, token: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let mut val = HeaderValue::from_str(format!("token {}", token).as_str()).unwrap();
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
        let base_url = std::env::var("FORGEJO_BASE_URL")?;
        let token = std::env::var("FORGEJO_TOKEN")?;
        Ok(Self::new(&base_url, &token))
    }

    #[allow(dead_code)]
    pub async fn list_all_orgs(&self) -> Result<Vec<Organization>, reqwest::Error> {
        let url = format!("{}/admin/orgs", self.base_url);
        let orgs = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<Organization>>()
            .await?;
        Ok(orgs)
    }

    #[allow(dead_code)]
    pub async fn org_list_teams(&self, org: &str) -> Result<Vec<Team>, reqwest::Error> {
        let url = format!("{}/orgs/{org}/teams", self.base_url);
        let teams = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<Team>>()
            .await?;
        Ok(teams)
    }

    #[allow(dead_code)]
    pub async fn get_team(&self, id: i64) -> Result<Team, reqwest::Error> {
        let url = format!("{}/teams/{id}", self.base_url);
        let team = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<Team>()
            .await?;
        Ok(team)
    }

    #[allow(dead_code)]
    pub async fn create_team(
        &self,
        org: &str,
        option: &CreateTeamOption,
    ) -> Result<Team, reqwest::Error> {
        let url = format!("{}/orgs/{org}/teams", self.base_url);

        let res = self.client.post(url).json(option).send().await?;
        if !res.status().is_success() {
            let body = res.text().await?;
            println!("{body}");
            panic!();
        }
        let team = res.json::<Team>().await?;
        Ok(team)
    }
}
