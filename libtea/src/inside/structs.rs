/*
RYOKUCHAT is a P2P chat application.

Copyright (C) 2021 TrendCreate
Copyright (C) 2021 WinLinux1028
Copyright (C) 2021 TRENDcreate

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

use ed448_rust::PublicKey;
use tokio::{io::AsyncWrite, sync::Mutex, task::JoinHandle};

use crate::UserData;

// SQLiteに入れておける形式のUserData
#[derive(sqlx::FromRow)]
pub(crate) struct UserDataRaw {
    pub id: Vec<u8>,
    pub hostname: String,
    pub username: Option<String>,
}

impl UserDataRaw {
    // UserDataに変換する
    pub fn to_userdata(&self) -> Option<UserData> {
        Some(UserData {
            id: PublicKey::try_from(self.id.as_slice()).ok()?,
            hostname: self.hostname.clone(),
            username: self.username.clone(),
        })
    }
}

// ユーザー情報のうち､ストレージに保存する必要が無いもの
#[allow(dead_code)]
pub(crate) struct UserDataTemp {
    pub send:
        Mutex<Box<dyn AsyncWrite + std::marker::Send + std::marker::Sync + std::marker::Unpin>>,
    pub handle: HandleWrapper,
}

// drop時にスレッドを終了するラッパー
pub(crate) struct HandleWrapper(pub JoinHandle<()>);

impl std::ops::Drop for HandleWrapper {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// 通信用の構造体
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub(crate) enum MessageForNetwork {
    DirectMsg(String),
}
