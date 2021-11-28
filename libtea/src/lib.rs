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

use std::{
    collections::HashMap, convert::TryFrom, future::Future, io::Cursor, path::PathBuf,
    time::Duration,
};

use byteorder::BigEndian;
use ed448_rust::{PrivateKey, PublicKey};
use libtor::{HiddenServiceVersion, Tor, TorAddress, TorFlag};
use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufStream},
    net::TcpListener,
    process::Command,
    sync::{mpsc::Sender, Mutex, RwLock},
    task::JoinHandle,
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
    socks_port: u16,
    user_database: Mutex<sqlx::SqliteConnection>,
    user_data_temp: RwLock<HashMap<[u8; 57], UserDataTemp>>,
    pub notify: Mutex<Option<Sender<Message>>>,
    pub myaddress: String,
}

/// メッセージの最大の長さです  
/// 125000バイトからヘッダーの2バイトを足したものです  
pub const MAXMSGLEN: usize = 125000 + 2;

impl RYOKUCHATSession {
    /// 動作の説明:  
    /// 新しくRYOKUCHATSessionを作ります  
    /// 引数について:  
    /// 1: libteaのデータを設置する場所をPathBufで指定します  
    /// 2: Torが使うSocksプロキシのポートを指定します  
    /// 3: Tor Hidden Serviceを経由して送られてきたリクエストを受け付けるためのポートを指定します  
    /// 返り値について:  
    /// Boxで包まれたRYOKUCHATSessionが返ってきます  
    pub async fn new(
        mut data_dir: PathBuf,
        socks_port: u16,
        ryokuchat_port: u16,
    ) -> Box<RYOKUCHATSession> {
        // ディレクトリを作成
        data_dir.push("tor");
        data_dir.push("hidden");
        let _ = fs::create_dir_all(&data_dir).await;
        data_dir.pop();
        data_dir.push("torrc");
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&data_dir);
        data_dir.pop();
        data_dir.pop();

        // SQLiteの初期化
        data_dir.push("sqlite.db");
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&data_dir);
        let mut sqlite =
            sqlx::SqliteConnection::connect(&format!("sqlite://{}", data_dir.to_str().unwrap()))
                .await
                .unwrap();
        sqlite
            .execute("CREATE TABLE IF NOT EXISTS users (lastupdate INTEGER NOT NULL, id BLOB NOT NULL, hostname TEXT NOT NULL, username TEXT);")
            .await
            .unwrap();
        data_dir.pop();

        #[cfg(not(target_os = "windows"))]
        Command::new("chmod")
            .arg("-R")
            .arg("700")
            .arg(data_dir.to_str().unwrap())
            .spawn()
            .unwrap()
            .wait()
            .await
            .unwrap();

        // Torを起動
        let mut tor_dir = data_dir.clone();
        tor_dir.push("tor");
        let mut hidden_dir = tor_dir.clone();
        hidden_dir.push("hidden");
        let mut tor_config = tor_dir.clone();
        tor_config.push("torrc");

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
                    Some(TorAddress::AddressPort("[::1]".to_string(), ryokuchat_port)).into(),
                ))
                .flag(TorFlag::SocksPortAddress(
                    TorAddress::AddressPort("[::1]".to_string(), socks_port),
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
        let mut secretkey: [u8; 57] = [0; 57];
        try_open_read(&data_dir, |mut f| async move {
            f.write_all(PrivateKey::new(&mut rand::rngs::OsRng).as_bytes())
                .await?;
            Ok(())
        })
        .await
        .unwrap()
        .read_exact(&mut secretkey)
        .await
        .unwrap();
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

        let mut session = Box::new(RYOKUCHATSession {
            handles: vec![HandleWrapper(torhandle)],
            myprivkey: secretkey,
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
            let listen = TcpListener::bind(format!("[::1]:{}", ryokuchat_port))
                .await
                .unwrap();
            loop {
                match listen.accept().await {
                    Ok((o, _)) => tokio::spawn(async move {
                        let mut stream = BufStream::new(o);
                        // 57バイトの公開鍵(ID)と8バイトのメッセージと114バイトの署名
                        let mut buf = [0; 57 + 8 + 114];
                        match stream.read_exact(&mut buf).await {
                            Ok(_) => (),
                            Err(_) => return,
                        }
                        let key = match PublicKey::try_from(&buf[0..57]) {
                            Ok(o) => o,
                            Err(_) => return,
                        };
                        // 連絡先リストに相手のアドレスがあることを確認

                        if let Some(s) = session.get_user_from_id(&key).await {
                            if s.id
                                .verify(&buf[57..57 + 8], &buf[57 + 8..57 + 8 + 114], None)
                                .is_ok()
                            {
                                process_message(session, key, stream).await;
                            }
                        }
                    }),
                    Err(_) => continue,
                };
            }
        });
        session.handles.push(HandleWrapper(handle));

        session
    }

    /// 動作の説明:  
    /// 実行された時点での連絡先リストを取得します  
    /// 返り値について:  
    /// VecDequeでArcに包まれたUserDataが返ってきます  
    /// 注意点:  
    /// 内部の連絡先リストと同期はされないため自分で変更を適用してください  
    pub async fn get_users(&self) -> Option<Vec<UserData>> {
        // self.number_to_data.read().await.clone()
        let mut users = self.user_database.lock().await;

        let user = sqlx::query_as::<_, UserDataRaw>(
            "SELECT id,hostname,username FROM users ORDER BY lastupdate DESC;",
        )
        .fetch_all(&mut *users)
        .await;

        match user {
            Ok(o) => Some(
                o.into_iter()
                    .map(|u| UserData {
                        id: PublicKey::try_from(u.id.as_slice()).unwrap(),
                        hostname: u.hostname,
                        username: u.username,
                    })
                    .collect(),
            ),
            Err(_) => None,
        }
    }

    /// 動作の説明:  
    /// IDからユーザー情報を取得します  
    /// 引数について:  
    /// IDを指定します  
    /// 返り値について:  
    /// データベースから取得したユーザー情報が返ってきます  
    pub async fn get_user_from_id(&self, id: &PublicKey) -> Option<UserData> {
        let mut users = self.user_database.lock().await;

        let user = match sqlx::query_as::<_, UserDataRaw>(
            "SELECT id,hostname,username FROM users WHERE id=? LIMIT 1;",
        )
        .bind(id.as_byte().as_slice())
        .fetch_optional(&mut *users)
        .await
        {
            Ok(o) => o,
            Err(_) => return None,
        };

        match user {
            Some(s) => Some(UserData {
                id: PublicKey::try_from(s.id.as_slice()).unwrap(),
                hostname: s.hostname,
                username: s.username,
            }),
            None => None,
        }
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
        let user = match decode_address(address) {
            Some(s) => s,
            None => return None,
        };

        let mut users = self.user_database.lock().await;

        match sqlx::query("SELECT id FROM users WHERE id=? LIMIT 1;")
            .bind(user.id.as_slice())
            .fetch_optional(&mut *users)
            .await
        {
            Ok(o) => {
                if o.is_none() {
                    match sqlx::query(
                        "INSERT INTO users (lastupdate, id, hostname) VALUES (?, ?, ?);",
                    )
                    .bind(chrono::Local::now().timestamp())
                    .bind(user.id.as_slice())
                    .bind(user.hostname)
                    .execute(&mut *users)
                    .await
                    {
                        Ok(_) => return Some(()),
                        Err(_) => return None,
                    }
                }
                None
            }
            Err(_) => None,
        }
    }

    /// 動作の説明:  
    /// 連絡先リストからユーザーを削除します  
    pub async fn del_user(&self, id: &PublicKey) -> Option<()> {
        let mut users = self.user_database.lock().await;
        match sqlx::query("DELETE FROM users WHERE id=?;")
            .bind(id.as_byte().as_slice())
            .execute(&mut *users)
            .await
        {
            Ok(_) => Some(()),
            Err(_) => None,
        }
    }

    /// 動作の説明:  
    /// メッセージを送信します  
    pub async fn send_msg(&self, id: &PublicKey, msg: &str) -> Option<()> {
        let msg = msg.trim();

        loop {
            let user_data_temp = self.user_data_temp.read().await;
            match user_data_temp.get(&id.as_byte()) {
                Some(s) => {
                    let send_data = MessageForNetwork::DirectMsg(msg.to_string());
                    let send_data = bincode::serialize(&send_data).ok()?;
                    let mut sender = s.send.lock().await;
                    sender
                        .write_all(&(send_data.len() as u64).to_be_bytes())
                        .await
                        .ok()?;
                    sender.write_all(&send_data).await.ok()?;
                    sender.flush().await.ok()?;
                    break;
                }
                None => {
                    drop(user_data_temp);
                    let user = match self.get_user_from_id(id).await {
                        Some(s) => s,
                        None => return None,
                    };
                    self.new_connection(user).await?;
                }
            }
        }
        Some(())
    }

    async fn new_connection(&self, userdata: UserData) -> Option<()> {
        let mut stream = match tokio_socks::tcp::Socks5Stream::connect(
            format!("[::1]:{}", self.socks_port).as_str(),
            format!("{}:4545", userdata.hostname),
        )
        .await
        {
            Ok(o) => o,
            Err(_) => return None,
        };

        // 57バイトの公開鍵(ID)を送信
        let pubkey = match PublicKey::try_from(&self.myprivkey) {
            Ok(o) => o,
            Err(_) => return None,
        };
        stream.write_all(&pubkey.as_byte()).await.ok()?;

        // 8バイトの検証用メッセージを送信
        let random = rand::rngs::OsRng.gen::<u64>().to_be_bytes();
        stream.write_all(&random).await.ok()?;

        // 114バイトの署名を送信
        let sign = match self.myprivkey.sign(&random, None) {
            Ok(o) => o,
            Err(_) => return None,
        };
        stream.write_all(&sign).await.ok()?;
        stream.flush().await.ok()?;

        process_message(self, userdata.id, stream).await;
        Some(())
    }

    async fn new_lastupdate(&self, id: &PublicKey) -> Option<()> {
        let mut users = self.user_database.lock().await;
        match sqlx::query("UPDATE users SET lastupdate=? WHERE id=? LIMIT 1;")
            .bind(chrono::Local::now().timestamp())
            .bind(id.as_byte().as_slice())
            .execute(&mut *users)
            .await
        {
            Ok(_) => Some(()),
            Err(_) => None,
        }
    }
}

/// 連絡先リストに含まれるユーザーのデータです
/// idにはそのユーザーのIDが内部表現で入っています
pub struct UserData {
    pub id: PublicKey,
    pub hostname: String,
    // stub: ユーザーネームを取得できるようにする
    pub username: Option<String>,
    // send: Mutex<
    //     Option<Box<dyn AsyncWrite + std::marker::Send + std::marker::Sync + std::marker::Unpin>>,
    // >,
    // handle: Mutex<Option<HandleWrapper>>,
}

impl UserData {
    /// 動作の説明:  
    /// アドレスを取得します  
    /// アドレスのフォーマットは(ユーザーID)@(Tor Hidden Serviceのホスト名)です  
    pub fn get_address(&self) -> String {
        let mut address = base64::encode_config(self.id.as_byte(), base64::URL_SAFE_NO_PAD);
        address.push('@');
        address.push_str(&self.hostname);
        address
    }
}

/// メッセージを受信するときに使います
pub enum Message {
    /// 新しい通常のメッセージが来た場合の情報を格納します  
    /// 1つ目にユーザーID、2つ目にメッセージが入ります  
    DirectMsg(PublicKey, String),
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
enum MessageForNetwork {
    DirectMsg(String),
}

// #[derive(serde::Serialize, serde::Deserialize)]
// struct Greeting {
//     DirectMsg(Vec<u8>, String),
// }

//以下非公開
#[derive(sqlx::FromRow)]
struct UserDataRaw {
    id: Vec<u8>,
    hostname: String,
    username: Option<String>,
}

#[allow(dead_code)]
struct UserDataTemp {
    send: Mutex<Box<dyn AsyncWrite + std::marker::Send + std::marker::Sync + std::marker::Unpin>>,
    handle: HandleWrapper,
}

struct HandleWrapper(JoinHandle<()>);

impl std::ops::Drop for HandleWrapper {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn process_message<
    T: 'static + AsyncRead + AsyncWrite + std::marker::Send + std::marker::Sync + std::marker::Unpin,
>(
    session: &RYOKUCHATSession,
    userid: PublicKey,
    stream: T,
) {
    let session = unsafe { std::mem::transmute::<&RYOKUCHATSession, &RYOKUCHATSession>(session) };
    let (mut read, write) = tokio::io::split(BufStream::new(stream));
    session.user_data_temp.write().await.insert(
        userid.as_byte(),
        UserDataTemp {
            send: Mutex::new(Box::new(write)),
            handle: HandleWrapper(tokio::spawn(async move {
                loop {
                    let a = process_message2(session, &userid, &mut read).await;
                    if a.is_none() {
                        session
                            .user_data_temp
                            .write()
                            .await
                            .remove(&userid.as_byte());
                        return;
                    }
                }
            })),
        },
    );
}

#[allow(clippy::collapsible_match, clippy::single_match)]
async fn process_message2<
    T: AsyncRead + std::marker::Send + std::marker::Sync + std::marker::Unpin,
>(
    session: &RYOKUCHATSession,
    userid: &PublicKey,
    read: &mut T,
) -> Option<()> {
    // メッセージのサイズを受信
    let mut len = [0; 8];
    read.read_exact(&mut len).await.ok()?;
    let mut len = Cursor::new(len);
    let len = match byteorder::ReadBytesExt::read_u64::<BigEndian>(&mut len) {
        Ok(len) => len,
        Err(_) => return None,
    };
    let len: usize = match TryFrom::try_from(len) {
        Ok(len) => len,
        Err(_) => return None,
    };
    if len < MAXMSGLEN {
        let mut msg = vec![0; len];
        read.read_exact(&mut msg).await.ok()?;
        let msg: MessageForNetwork = bincode::deserialize(&msg).ok()?;
        match msg {
            MessageForNetwork::DirectMsg(msg) => {
                // stub: メッセージ履歴の保存を実装
                session.new_lastupdate(userid).await;

                match &mut *session.notify.lock().await {
                    Some(s) => {
                        let userid = userid.clone();
                        let _ = s.send(Message::DirectMsg(userid, msg)).await;
                    }
                    None => (),
                }
                return Some(());
            }
        }
    }
    None
}

fn decode_address(address: &str) -> Option<UserDataRaw> {
    let mut address = address.split('@');

    let key = match address.next() {
        Some(s) => s,
        None => return None,
    };
    let key = match base64::decode_config(key, base64::URL_SAFE_NO_PAD) {
        Ok(o) => o,
        Err(_) => return None,
    };

    let hostname = match address.next() {
        Some(s) => s.to_string(),
        None => return None,
    };

    Some(UserDataRaw {
        id: key,
        hostname,
        username: None,
    })
}

async fn try_open_read<
    F: Fn(fs::File) -> R,
    R: Future<Output = Result<(), Box<dyn std::error::Error>>>,
>(
    path: &std::path::Path,
    initfn: F,
) -> Result<fs::File, Box<dyn std::error::Error>> {
    if let Ok(o) = fs::File::open(&path).await {
        return Ok(o);
    }

    if let Ok(o) = fs::File::create(&path).await {
        initfn(o).await?;
        return Ok(fs::File::open(&path).await?);
    }

    panic!("Could not open and create {:?}", path);
}
