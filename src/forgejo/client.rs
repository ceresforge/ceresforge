use std::collections::HashMap;

use crate::forgejo::{Organization, Permission, Repository, Team, User, Visibility};
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
pub struct CreateForkOption {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum AddCollaboratorPermission {
    Read,
    Write,
    Admin,
}

#[derive(Debug, Default, Serialize)]
pub struct AddCollaboratorOption {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission: Option<AddCollaboratorPermission>,
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

#[derive(Debug, Default, Serialize)]
pub struct CreateUserOption {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub must_change_password: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restricted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_notify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_id: Option<i64>,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,
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
    pub async fn list_all_users(&self) -> Result<Vec<User>, reqwest::Error> {
        let url = format!("{}/admin/users", self.base_url);
        let users = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<User>>()
            .await?;
        Ok(users)
    }

    #[allow(dead_code)]
    pub async fn create_user(&self, option: &CreateUserOption) -> Result<User, reqwest::Error> {
        let url = format!("{}/admin/users", self.base_url);
        let user = self
            .client
            .post(url)
            .json(option)
            .send()
            .await?
            .error_for_status()?
            .json::<User>()
            .await?;
        Ok(user)
    }

    #[allow(dead_code)]
    pub async fn get_user(&self, username: &str) -> Result<User, reqwest::Error> {
        let url = format!("{}/users/{username}", self.base_url);
        let user = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<User>()
            .await?;
        Ok(user)
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

    #[allow(dead_code)]
    pub async fn add_team_member(&self, id: i64, username: &str) -> Result<(), reqwest::Error> {
        let url = format!("{}/teams/{id}/members/{username}", self.base_url);
        let res = self.client.put(url).send().await?;
        if !res.status().is_success() {
            let body = res.text().await?;
            println!("{body}");
            panic!();
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_repository(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Repository, reqwest::Error> {
        let url = format!("{}/repos/{owner}/{repo}", self.base_url);
        let repository = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<Repository>()
            .await?;
        Ok(repository)
    }

    #[allow(dead_code)]
    pub async fn create_fork(
        &self,
        owner: &str,
        repo: &str,
        option: &CreateForkOption,
        sudo: Option<&str>,
    ) -> Result<Repository, reqwest::Error> {
        let url = format!("{}/repos/{owner}/{repo}/forks", self.base_url);
        let mut request = self.client.post(url).json(option);
        if let Some(username) = sudo {
            request = request.header("Sudo", username);
        }
        let res = request.send().await?;
        if !res.status().is_success() {
            let body = res.text().await?;
            println!("{body}");
            panic!();
        }
        let repository = res.json::<Repository>().await?;
        Ok(repository)
    }

    #[allow(dead_code)]
    pub async fn add_collaborator(
        &self,
        owner: &str,
        repo: &str,
        collaborator: &str,
        option: &AddCollaboratorOption,
        sudo: Option<&str>,
    ) -> Result<(), reqwest::Error> {
        let url = format!("{}/repos/{owner}/{repo}/collaborators/{collaborator}", self.base_url);
        let mut request = self.client.put(url).json(option);
        if let Some(username) = sudo {
            request = request.header("Sudo", username);
        }
        let res = request.send().await?;
        if !res.status().is_success() {
            let body = res.text().await?;
            println!("{body}");
            panic!();
        }
        Ok(())
    }
}
