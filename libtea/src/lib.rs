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

#[macro_use]
mod inside;
pub mod consts;

#[macro_use]
extern crate log;

use crate::{
    consts::{KEY_LENGTH, SIG_LENGTH},
    inside::{
        functions::{decode_address, greeting_auth, process_message, try_open_read},
        structs::{ErrMsg, HandleWrapper, MessageForNetwork, UserDataRaw, UserDataTemp},
    },
};

use std::{collections::HashMap, convert::TryFrom, net::IpAddr, path::PathBuf, time::Duration};

use ed448_rust::{PrivateKey, PublicKey};
use libtor::{HiddenServiceVersion, Tor, TorAddress, TorFlag};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt, BufStream},
    net::TcpListener,
    process::Command,
    sync::{mpsc::Sender, Mutex, RwLock},
};

use rand::Rng;

use sqlx::{Connection, Executor};

/// libteaのセッションです  
/// newメソッドを使うことで生成できます  
/// notifyのMutexの中身を書き換えることで新規メッセージの通知を受け取ることができます  
/// myaddressには自分のアドレスが入っており、共有することで他の人と通信することができます  
pub struct RYOKUCHATSession {
    handles: Vec<HandleWrapper>,
    myprivkey: PrivateKey,
    localhost: String,
    socks_port: u16,
    user_database: Mutex<sqlx::SqliteConnection>,
    user_data_temp: RwLock<HashMap<[u8; KEY_LENGTH], UserDataTemp>>,
    pub notify: Mutex<Option<Sender<Message>>>,
    myaddress: String,
}

impl RYOKUCHATSession {
    /// 動作の説明:  
    /// 新しくRYOKUCHATSessionを作ります  
    /// 引数について:  
    /// 1: libteaのデータを設置する場所をPathBufで指定します  
    /// 2: Torが使うSocksプロキシのポートを指定します  
    /// 3: Tor Hidden Serviceを経由して送られてきたリクエストを受け付けるためのポートを指定します  
    /// 返り値について:  
    /// Boxで包まれたRYOKUCHATSessionが返ってきます  
    pub async fn new(mut data_dir: PathBuf, port: u16) -> Box<RYOKUCHATSession> {
        trace!("RYOKUCHATSession::new() is called.");
        defer!(trace!("reterning from RYOKUCHATSession::new()"));
        debug!("data_dir is {:?}", &data_dir);

        // それぞれの用途のポート番号を決める
        let ryokuchat_port = port;
        let socks_port = port + 1;
        debug!("ryokuchat_port is {}", ryokuchat_port);
        debug!("socks_port is {}", socks_port);

        // localhostのアドレスを取得
        let localhost = match tokio::net::lookup_host("localhost:1")
            .await
            .unwrap()
            .next()
            .unwrap()
            .ip()
        {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => "[".to_string() + &v6.to_string() + "]",
        };
        debug!("localhost is {}", localhost);

        // ディレクトリを作成
        data_dir.push("tor");
        data_dir.push("hidden");
        let _ = fs::create_dir_all(&data_dir).await;
        info!("directory {:?} is created", &data_dir);

        data_dir.pop();
        data_dir.push("torrc");
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&data_dir);
        info!("file {:?} is created", &data_dir);
        data_dir.pop();
        data_dir.pop();

        // SQLiteの初期化
        data_dir.push("sqlite.db");
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&data_dir);
        info!("file {:?} is created", &data_dir);
        let mut sqlite =
            sqlx::SqliteConnection::connect(&format!("sqlite://{}", data_dir.to_str().unwrap()))
                .await
                .unwrap();
        sqlite
            .execute("CREATE TABLE IF NOT EXISTS users (lastupdate INTEGER NOT NULL, id BLOB NOT NULL, hostname TEXT NOT NULL, username TEXT);")
            .await
            .unwrap();
        sqlite
            .execute("CREATE INDEX IF NOT EXISTS search ON users(lastupdate, id);")
            .await
            .unwrap();
        data_dir.pop();

        #[cfg(not(target_os = "windows"))]
        {
            Command::new("chmod")
                .arg("-R")
                .arg("1700")
                .arg(data_dir.to_str().unwrap())
                .spawn()
                .unwrap()
                .wait()
                .await
                .unwrap();
            info!("permission of directory {:?} is set to 1700", &data_dir);
        }

        // Torを起動
        let mut tor_dir = data_dir.clone();
        tor_dir.push("tor");
        let mut hidden_dir = tor_dir.clone();
        hidden_dir.push("hidden");
        let mut tor_config = tor_dir.clone();
        tor_config.push("torrc");
        debug!("DataDirectory of Tor is {:?}", &tor_dir);
        debug!("HiddenServiceDir of Tor is {:?}", &hidden_dir);
        debug!("ConfigFile of Tor is {:?}", &tor_config);
        let localhost2 = localhost.clone();
        let torhandle = tokio::task::spawn_blocking(move || {
            Tor::new()
                .flag(TorFlag::Quiet())
                .flag(TorFlag::DataDirectory(
                    tor_dir.to_str().unwrap().to_string(),
                ))
                .flag(TorFlag::ConfigFile(
                    tor_config.to_str().unwrap().to_string(),
                ))
                .flag(TorFlag::HiddenServiceDir(
                    hidden_dir.to_str().unwrap().to_string(),
                ))
                .flag(TorFlag::HiddenServiceVersion(HiddenServiceVersion::V3))
                .flag(TorFlag::HiddenServicePort(
                    TorAddress::Port(4545),
                    Some(TorAddress::AddressPort(localhost2.clone(), ryokuchat_port)).into(),
                ))
                .flag(TorFlag::SocksPortAddress(
                    TorAddress::AddressPort(localhost2.clone(), socks_port),
                    None.into(),
                    None.into(),
                ))
                .flag(TorFlag::ExcludeNodes(vec!["SlowServer".to_string()].into()))
                .flag(TorFlag::StrictNodes(true.into()))
                .flag(TorFlag::ConnectionPadding(true.into()))
                .flag(TorFlag::ReducedConnectionPadding(false.into()))
                .flag(TorFlag::CircuitPadding(true.into()))
                .flag(TorFlag::ReducedCircuitPadding(false.into()))
                .start()
                .unwrap();
        });

        // 秘密鍵を読み出し､鍵のペアを用意する
        data_dir.push("DO_NOT_SEND_TO_OTHER_PEOPLE_secretkey.ykr");
        let mut secretkey = [0; KEY_LENGTH];
        try_open_read(&data_dir, |mut f| async move {
            info!("generating new secretkey");
            f.write_all(PrivateKey::new(&mut rand::rngs::OsRng).as_bytes())
                .await?;
            Ok(())
        })
        .await
        .unwrap()
        .read_exact(&mut secretkey)
        .await
        .unwrap();
        info!("{:?} is read", &data_dir);
        let secretkey = PrivateKey::try_from(&secretkey).unwrap();
        let publickey = PublicKey::try_from(&secretkey).unwrap();
        data_dir.pop();

        // 公開鍵とTorのホスト名から自分のアドレスを生成する
        data_dir.push("tor");
        data_dir.push("hidden");
        data_dir.push("hostname");
        let mut address = base64::encode_config(publickey.as_byte(), base64::URL_SAFE_NO_PAD);
        address.push('@');
        let mut hostname = String::new();
        loop {
            if let Ok(mut o) = fs::File::open(&data_dir).await {
                if o.read_to_string(&mut hostname).await.is_ok()
                    && hostname.trim().ends_with(".onion")
                {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        address.push_str(hostname.trim());
        debug!("myaddress is {}", &address);

        let mut session = Box::new(RYOKUCHATSession {
            handles: vec![HandleWrapper(torhandle)],
            myprivkey: secretkey,
            localhost,
            socks_port,
            user_database: Mutex::const_new(sqlite),
            user_data_temp: RwLock::const_new(HashMap::new()),
            notify: Mutex::const_new(None),
            myaddress: address,
        });

        // メッセージを受信するスレッドを作る
        // ライフタイムエラーを消すためにtransmuteを使っているが、RYOKUCHATSessionには書き換えられうる値にはMutexやRwLockを使っており、RYOKUCHATSessionの実体はヒープ上にあるので安全
        let s = unsafe { std::mem::transmute::<&RYOKUCHATSession, &RYOKUCHATSession>(&*session) };
        let handle = tokio::spawn(async move {
            let session = s;
            let listen = TcpListener::bind(format!("{}:{}", &session.localhost, ryokuchat_port))
                .await
                .unwrap();
            debug!("listen loop started");
            loop {
                if let Ok((o, _)) = listen.accept().await {
                    tokio::spawn(async move {
                        info!("new connection come");

                        let mut stream = BufStream::new(o);

                        // 57バイトの公開鍵(ID)
                        let mut key = [0; KEY_LENGTH];
                        stream.read_exact(&mut key).await.ok()?;
                        let key = PublicKey::try_from(&key)
                            .err_exec(|e| error!("{}", e))
                            .ok()?;

                        // 連絡先リストに相手のアドレスがあることを確認
                        let user = session
                            .get_user_from_id(&key)
                            .await
                            .err_exec(|_| error!("This connection is from an unknown source."))?;

                        // 16バイトの認証用メッセージ
                        let auth = rand::rngs::OsRng.gen::<u128>().to_be_bytes();
                        stream.write_all(&auth).await.ok()?;
                        stream.flush().await.ok()?;
                        let mut sign = [0; SIG_LENGTH];
                        stream.read_exact(&mut sign).await.ok()?;
                        user.id
                            .verify(&greeting_auth(&auth)?, &sign, None)
                            .err_exec(|_| error!("failed to verify the connection source"))
                            .ok()?;

                        info!("this connection is from {}", user.get_address());

                        process_message(session, key, stream).await;
                        Some(())
                    });
                }
            }
        });
        session.handles.push(HandleWrapper(handle));

        session
    }

    /// 動作の説明:  
    /// 自分自身のアドレスを取得します  
    /// これを相手に渡すことで通信が出来ます  
    pub fn myaddress(&self) -> &str {
        trace!("RYOKUCHATSession::myaddress() is called");
        defer!(trace!("returning from RYOKUCHATSession::myaddress()"));

        debug!("self.myaddress is {}", &self.myaddress);
        &self.myaddress
    }

    /// 動作の説明:  
    /// 実行された時点での連絡先リストを取得します  
    /// 注意点:  
    /// 内部の連絡先リストと同期はされないため自分で変更を適用するか定期的に再取得してください  
    pub async fn get_users(&self) -> Option<Vec<UserData>> {
        trace!("RYOKUCHATSession::get_users() is called");
        defer!(trace!("returning from RYOKUCHATSession::get_users()"));

        let mut database = self.user_database.lock().await;

        let users = sqlx::query_as::<_, UserDataRaw>(
            "SELECT id,hostname,username FROM users ORDER BY lastupdate DESC;",
        )
        .fetch_all(&mut *database)
        .await
        .err_exec(|e| error!("{}", e))
        .ok()?;
        drop(database);

        let users = users
            .into_iter()
            .map(|u| u.to_userdata().unwrap())
            .collect();

        Some(users)
    }

    /// 動作の説明:  
    /// IDからユーザー情報を取得します  
    /// 引数について:  
    /// 引数にはIDを入れてください
    /// 返り値について:  
    /// 成功ならばSomeに包まれたユーザー情報が、失敗ならばNoneが返ります  
    pub async fn get_user_from_id(&self, id: &PublicKey) -> Option<UserData> {
        trace!("RYOKUCHATSession::get_user_from_id() is called");
        defer!(trace!(
            "returning from RYOKUCHATSession::get_user_from_id()"
        ));

        let mut users = self.user_database.lock().await;

        let users = sqlx::query_as::<_, UserDataRaw>(
            "SELECT id,hostname,username FROM users WHERE id=? LIMIT 1;",
        )
        .bind(id.as_byte().as_slice())
        .fetch_optional(&mut *users)
        .await
        .err_exec(|e| error!("{}", e))
        .ok()?;

        users.err_exec(|_| error!("unknown id"))?.to_userdata()
    }

    /// 動作の説明:  
    /// 連絡先リストにユーザーを追加します  
    /// 引数について:  
    /// 引数には&str型でアドレスを入れてください  
    /// アドレスは以下のような形式になります  
    /// (ユーザーID)@(Tor Hidden Serviceのドメイン名)  
    /// 返り値について:  
    /// 成功ならばSome(())、失敗ならばNoneが返ります  
    pub async fn add_user(&self, address: &str) -> Option<()> {
        trace!("RYOKUCHATSession::add_user() is called");
        defer!(trace!("returning from RYOKUCHATSession::add_user()"));
        debug!("address is {}", address);

        let user = decode_address(address)?;

        match self.get_user_from_id(&user.id).await {
            None => {
                let mut users = self.user_database.lock().await;

                match sqlx::query("INSERT INTO users (lastupdate, id, hostname) VALUES (?, ?, ?);")
                    .bind(chrono::Local::now().timestamp())
                    .bind(user.id.as_byte().as_slice())
                    .bind(user.hostname)
                    .execute(&mut *users)
                    .await
                {
                    Ok(_) => Some(()),
                    Err(e) => {
                        error!("{}", e);
                        None
                    }
                }
            }
            Some(_) => None,
        }
    }

    /// 動作の説明:  
    /// 連絡先リストからユーザーを削除します  
    /// 引数について:  
    /// 引数にはIDを入れてください  
    /// 返り値について:  
    /// 成功ならばSome(())が、失敗ならばNoneが返ります  
    pub async fn del_user(&self, id: &PublicKey) -> Option<()> {
        trace!("RYOKUCHATSession::del_user() is called");
        defer!(trace!("returning from RYOKUCHATSession::del_user()"));

        let mut users = self.user_database.lock().await;
        match sqlx::query("DELETE FROM users WHERE id=?;")
            .bind(id.as_byte().as_slice())
            .execute(&mut *users)
            .await
        {
            Ok(_) => Some(()),
            Err(e) => {
                error!("{}", e);
                None
            }
        }
    }

    /// 動作の説明:  
    /// メッセージを送信します  
    /// 引数について:  
    /// 第1引数にはIDを入れてください  
    /// 第2引数には送信したいメッセージを入れます  
    /// 返り値について:  
    /// 成功ならばSome(())が、失敗ならばNoneが返ります  
    pub async fn send_dm(&self, id: &PublicKey, msg: &str) -> Option<()> {
        trace!("RYOKUCHATSession::send_dm() is called");
        defer!(trace!("returning from RYOKUCHATSession::send_dm()"));

        let msg = msg.trim();
        info!("msg is {}", &msg);
        if msg.is_empty() {
            error!("tried to send a blank message");
            return None;
        }

        let send_data = MessageForNetwork::DirectMsg(msg.to_string());
        let send_data = bincode::serialize(&send_data)
            .err_exec(|e| error!("{}", e))
            .ok()?;

        self.send(id, &send_data).await?;
        self.new_lastupdate(id).await?;

        Some(())
    }

    // 相手にデータを送信する
    async fn send(&self, id: &PublicKey, data: &[u8]) -> Option<()> {
        trace!("RYOKUCHATSession::send() is called");
        defer!(trace!("returning from RYOKUCHATSession::send()"));

        self.new_connection(id)
            .await
            .err_exec(|_| error!("failed to connect"))?;

        let user_data_temp = self.user_data_temp.read().await;
        let user_data_temp = user_data_temp
            .get(&id.as_byte())
            .err_exec(|_| error!("something went wrong"))?;

        let data_sign = self
            .myprivkey
            .sign(data, None)
            .err_exec(|e| error!("{}", e))
            .ok()?;

        let mut sender = user_data_temp.send.lock().await;
        sender
            .write_all(&(data.len() as u64).to_be_bytes())
            .await
            .ok()?;
        sender.write_all(data).await.ok()?;
        sender.write_all(&data_sign).await.ok()?;
        sender.flush().await.ok()?;
        drop(sender);

        Some(())
    }

    // 新しく接続を開始する
    async fn new_connection(&self, id: &PublicKey) -> Option<()> {
        trace!("RYOKUCHATSession::new_connection() is called");
        defer!(trace!("returning from RYOKUCHATSession::new_connection()"));

        let user_data_temp = self.user_data_temp.read().await;
        match user_data_temp.get(&id.as_byte()) {
            Some(_) => {
                info!("already connected");
            }
            None => {
                info!("connecting to the other party...");
                drop(user_data_temp);

                let userdata = self.get_user_from_id(id).await?;
                let stream = tokio_socks::tcp::Socks5Stream::connect(
                    format!("{}:{}", &self.localhost, self.socks_port).as_str(),
                    format!("{}:4545", userdata.hostname),
                )
                .await
                .err_exec(|e| error!("{}", e))
                .ok()?;
                let mut stream = BufStream::new(stream);
                info!("created new connection");

                // 57バイトの公開鍵(ID)
                let pubkey = PublicKey::try_from(&self.myprivkey).ok()?;
                stream.write_all(&pubkey.as_byte()).await.ok()?;
                stream.flush().await.ok()?;

                // 16バイトの検証用メッセージ
                let mut auth = [0; 16];
                stream.read_exact(&mut auth).await.ok()?;

                // 114バイトの署名
                let sign = self.myprivkey.sign(&greeting_auth(&auth)?, None).ok()?;
                stream.write_all(&sign).await.ok()?;
                stream.flush().await.ok()?;

                process_message(self, userdata.id, stream).await;
            }
        }
        Some(())
    }

    // ユーザーの最終更新を現在の時刻に変更する
    async fn new_lastupdate(&self, id: &PublicKey) -> Option<()> {
        trace!("RYOKUCHATSession::new_lastupdate() is called");
        defer!(trace!("returning from RYOKUCHATSession::new_lastupdate()"));

        let timestamp = chrono::Local::now().timestamp();
        debug!("timestamp is {}", timestamp);

        let mut users = self.user_database.lock().await;
        sqlx::query("UPDATE users SET lastupdate=? WHERE id=?;")
            .bind(timestamp)
            .bind(id.as_byte().as_slice())
            .execute(&mut *users)
            .await
            .err_exec(|e| error!("{}", e))
            .ok()?;
        drop(users);

        Some(())
    }
}

/// 連絡先リストに含まれるユーザーのデータです
/// idにはそのユーザーのIDが内部表現で入っています
pub struct UserData {
    pub id: PublicKey,
    pub hostname: String,
    // stub: ユーザーネームを取得できるようにする
    pub username: Option<String>,
}

impl UserData {
    /// 動作の説明:  
    /// アドレスを取得します  
    /// アドレスのフォーマットは(ユーザーID)@(Tor Hidden Serviceのホスト名)です  
    pub fn get_address(&self) -> String {
        trace!("UserData::get_address() is called");
        defer!(trace!("returning from UserData::get_address()"));

        let mut address = base64::encode_config(self.id.as_byte(), base64::URL_SAFE_NO_PAD);
        address.push('@');
        address.push_str(&self.hostname);

        debug!("address is {}", &address);
        address
    }
}

/// メッセージを受信するときに使います
pub enum Message {
    /// 新しい通常のメッセージが来た場合の情報を格納します  
    /// 1つ目にユーザーID、2つ目にメッセージが入ります  
    DirectMsg(PublicKey, String),
}
