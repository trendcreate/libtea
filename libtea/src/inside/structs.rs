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
pub struct UserDataRaw {
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
pub struct UserDataTemp {
    pub send:
        Mutex<Box<dyn AsyncWrite + std::marker::Send + std::marker::Sync + std::marker::Unpin>>,
    pub handle: HandleWrapper,
}

// drop時にスレッドを終了するラッパー
pub struct HandleWrapper(pub JoinHandle<()>);

impl std::ops::Drop for HandleWrapper {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// 通信用の構造体
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum MessageForNetwork {
    DirectMsg(String),
}

// デバッグメッセージの表示を簡略化するためのトレイト
pub trait ErrMsg<F: FnOnce(&str)> {
    fn err_exec(self, function: F) -> Self;
}

impl<F: FnOnce(&str), T, E: std::fmt::Debug> ErrMsg<F> for std::result::Result<T, E> {
    fn err_exec(self, function: F) -> Self {
        match &self {
            Ok(_) => {}
            Err(e) => {
                function(&format!("{:?}", e));
            }
        }
        self
    }
}

impl<F: FnOnce(&str), T> ErrMsg<F> for std::option::Option<T> {
    fn err_exec(self, function: F) -> Self {
        match &self {
            Some(_) => {}
            None => {
                function("");
            }
        }
        self
    }
}

pub struct DeferWrapper<F: FnMut()> {
    pub f: F,
}

impl<F: FnMut()> DeferWrapper<F> {
    pub fn new(f: F) -> DeferWrapper<F> {
        DeferWrapper { f }
    }
}

impl<F: FnMut()> Drop for DeferWrapper<F> {
    fn drop(&mut self) {
        (self.f)();
    }
}
