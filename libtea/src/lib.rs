use std::{
    collections::{HashMap, VecDeque},
    convert::TryFrom,
    future::Future,
    io::Cursor,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use byteorder::BigEndian;
use ed448_rust::{PrivateKey, PublicKey};
use libtor::{HiddenServiceVersion, Tor, TorAddress, TorFlag};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::{mpsc::Sender, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard},
    task::JoinHandle,
};

/// libteaのセッションです  
/// newメソッドを使うことで生成できます  
/// notifyのMutexの中身を書き換えることで新規メッセージの通知を受け取ることができます  
/// myaddressには自分のアドレスが入っており、共有することで他の人と通信することができます  
pub struct RYOKUCHATSession<'a> {
    handles: Vec<HandleWrapper>,
    myprivkey: PrivateKey,
    number_to_data: RwLock<VecDeque<Arc<UserData>>>,
    userid_to_data: RwLock<HashMap<&'a PublicKey, Arc<UserData>>>,
    pub notify: Mutex<Option<Sender<Message>>>,
    pub myaddress: String,
}

/// メッセージの最大の長さです  
/// 125000バイトからヘッダーの187バイトを引いたものです  
pub const MAXMSGLEN: usize = 125000 - 57 - 8 - 114 - 8;

impl<'a> RYOKUCHATSession<'a> {
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
    ) -> Box<RYOKUCHATSession<'a>> {
        // ディレクトリを作成
        data_dir.push("tor");
        let _ = fs::create_dir_all(&data_dir).await;
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
        let data_dir2 = data_dir.clone();
        data_dir.push("tor");
        let torhandle = tokio::task::spawn_blocking(move || {
            Tor::new()
                .flag(TorFlag::Quiet())
                .flag(TorFlag::ExcludeNodes(vec!["SlowServer".to_string()].into()))
                .flag(TorFlag::SocksPortAddress(
                    TorAddress::AddressPort("[::1]".to_string(), socks_port),
                    None.into(),
                    None.into(),
                ))
                .flag(TorFlag::HiddenServiceDir(
                    data_dir.to_str().unwrap().to_string(),
                ))
                .flag(TorFlag::HiddenServiceVersion(HiddenServiceVersion::V3))
                .flag(TorFlag::HiddenServicePort(
                    TorAddress::Port(4545),
                    Some(TorAddress::AddressPort("[::1]".to_string(), ryokuchat_port)).into(),
                ))
                .start()
                .unwrap();
        });
        let mut data_dir = data_dir2;

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

        // 連絡先リストを読み出す
        let mut addressbook = String::new();
        data_dir.push("AddressBook.ron");
        try_open_read(&data_dir, |mut f| async move {
            f.write_all(ron::to_string(&UserDatas(Vec::new()))?.as_bytes())
                .await?;
            Ok(())
        })
        .await
        .unwrap()
        .read_to_string(&mut addressbook)
        .await
        .unwrap();
        let addressbook: VecDeque<Arc<UserData>> = ron::from_str::<UserDatas>(&addressbook)
            .unwrap()
            .0
            .into_iter()
            .map(|a| {
                let mut b = decode_address(&a.0).unwrap();
                b.username = RwLock::const_new(a.1);
                Arc::new(b)
            })
            .collect();
        data_dir.pop();

        // ユーザーIDからそれに対応するデータを引けるHashMapを作る
        let mut userid_to_data = HashMap::new();
        for i in &addressbook {
            // ライフタイムを騙しているが、addressbookの中のiはヒープ上にあり、addressbook自体もuserid_to_dataと一緒にRYOKUCHATSessionに格納されるため安全
            unsafe {
                userid_to_data.insert(
                    std::mem::transmute::<&PublicKey, &PublicKey>(&i.id),
                    Arc::clone(i),
                );
            }
        }

        // 公開鍵とTorのホスト名から自分のアドレスを生成する
        data_dir.push("tor");
        data_dir.push("hostname");
        let mut address =
            base64::encode_config(publickey.as_bytes().unwrap(), base64::URL_SAFE_NO_PAD);
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
            number_to_data: RwLock::const_new(addressbook),
            userid_to_data: RwLock::const_new(userid_to_data),
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
                        if let Some(s) = session.userid_to_data.write().await.get(&key) {
                            if s.id
                                .verify(&buf[57..57 + 8], &buf[57 + 8..57 + 8 + 114], None)
                                .is_ok()
                            {
                                let (mut read, write) = tokio::io::split(stream);
                                *s.send.lock().await = Some(write);
                                *s.handle.lock().await =
                                    Some(HandleWrapper(tokio::spawn(async move {
                                        loop {
                                            match process_message(session, &key, &mut read).await {
                                                Some(_) => continue,
                                                None => return,
                                            }
                                        }
                                    })));
                            }
                        };
                    }),
                    Err(_) => continue,
                };
            }
        });
        session.handles.push(HandleWrapper(handle));

        session
    }

    /// 動作の説明:  
    /// 連絡先リストをロックし取得します  
    /// 返り値について:  
    /// RwLockWriteGuardで包まれたVecDequeで連絡先が返ってきます  
    /// 注意点:  
    /// このメソッドで取得した連絡先はdropされない限り読み書き要求を永久にブロックし続けます  
    /// パフォーマンスに影響するため、使い終わったらすぐにdrop()を使ってドロップしてください  
    pub async fn get_users_and_lock(&'a self) -> RwLockWriteGuard<'a, VecDeque<Arc<UserData>>> {
        self.number_to_data.write().await
    }

    /// 動作の説明:  
    /// 実行された時点での連絡先リストを取得します  
    /// 返り値について:  
    /// VecDequeでArcに包まれたUserDataが返ってきます  
    /// 注意点:  
    /// get_users_and_lockのようにロックしたりはしませんが、内部の連絡先リストと同期はされないため自分で変更を適用してください  
    pub async fn get_users(&self) -> VecDeque<Arc<UserData>> {
        self.number_to_data.read().await.clone()
    }

    pub async fn get_user_from_id(id: &PublicKey) {}

    /// 動作の説明:  
    /// 連絡先リストにユーザーを追加します  
    /// 引数について:  
    /// 引数には&str型でアドレスを入れてください  
    /// アドレスは以下のような形式になります  
    /// (ユーザーID)@(Tor Hidden Serviceのドメイン名)  
    /// 返り値について:  
    /// 成功ならばSome(())、失敗ならばNoneが返ります  
    pub async fn add_user(&self, address: &str) -> Option<()> {
        match decode_address(address) {
            Some(s) => {
                let s = Arc::new(s);
                self.number_to_data.write().await.push_front(Arc::clone(&s));

                // ライフタイムを騙しているが、sの実体はヒープ上にあり、sをcloneしたものはRYOKUCHATSessionが消えるまで存在し続けるため安全
                unsafe {
                    self.userid_to_data.write().await.insert(
                        std::mem::transmute::<&PublicKey, &PublicKey>(&s.id),
                        Arc::clone(&s),
                    );
                }
                Some(())
            }
            None => None,
        }
    }

    /// 動作の説明:  
    /// 連絡先リストからユーザーを削除します  
    ///
    pub async fn del_user(
        &self,
        index: usize,
        data: &mut RwLockWriteGuard<'a, VecDeque<Arc<UserData>>>,
    ) {
        data.remove(index);
    }
}

/// 連絡先リストに含まれるユーザーのデータです
/// idにはそのユーザーのIDが内部表現で入っています  
pub struct UserData {
    pub id: PublicKey,
    hostname: String,
    // stub: ユーザーネームを取得できるようにする
    username: RwLock<Option<String>>,
    send: Mutex<Option<WriteHalf<BufStream<TcpStream>>>>,
    handle: Mutex<Option<HandleWrapper>>,
}

impl UserData {
    /// 動作の説明:  
    /// ユーザー名を取得します  
    /// 注意点:  
    /// ユーザー名の領域をロックするため、なるべく早くdrop()してください  
    pub async fn get_username(&'_ self) -> RwLockReadGuard<'_, Option<String>> {
        self.username.read().await
    }

    /// 動作の説明:  
    /// アドレスを取得します  
    /// アドレスのフォーマットは(ユーザーID)@(Tor Hidden Serviceのホスト名)です  
    pub async fn get_address(&self) -> String {
        let mut address =
            base64::encode_config(self.id.as_bytes().unwrap(), base64::URL_SAFE_NO_PAD);
        address.push_str(&self.hostname);
        address
    }
}

/// メッセージを受信するときに使います
pub enum Message {
    /// 新しい通常のメッセージが来た場合の情報を格納します  
    /// 1つ目にユーザーID、2つ目にメッセージが入ります  
    NewMsg(PublicKey, String),
}

//以下非公開
#[derive(serde::Serialize, serde::Deserialize)]
struct UserDatas(Vec<(String, Option<String>)>);

struct HandleWrapper(JoinHandle<()>);

impl std::ops::Drop for HandleWrapper {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[allow(clippy::collapsible_match, clippy::single_match)]
async fn process_message(
    session: &RYOKUCHATSession<'_>,
    userid: &PublicKey,
    read: &mut ReadHalf<BufStream<TcpStream>>,
) -> Option<()> {
    // メッセージのサイズを受信
    let mut len = [0; 8];
    if read.read_exact(&mut len).await.is_ok() {
        let mut len = Cursor::new(len);
        let len = match byteorder::ReadBytesExt::read_u64::<BigEndian>(&mut len) {
            Ok(len) => len,
            Err(_) => return None,
        };
        let len: usize = match TryFrom::try_from(len) {
            Ok(len) => len,
            Err(_) => return None,
        };
        if 2 < len && len < MAXMSGLEN {
            // メッセージ種別を受信
            let mut buf = vec![0; len];
            if read.read_exact(&mut buf).await.is_ok() {
                let mut kind = Cursor::new(&buf[..2]);
                let kind = match byteorder::ReadBytesExt::read_u16::<BigEndian>(&mut kind) {
                    Ok(kind) => kind,
                    Err(_) => return None,
                };
                match kind {
                    0 => {
                        let msg = &buf[2..];
                        let msg = match std::str::from_utf8(msg) {
                            Ok(msg) => msg,
                            Err(_) => return None,
                        };
                        // stub: メッセージ履歴の保存を実装
                        let mut number_to_data = session.number_to_data.write().await;
                        let index = number_to_data.iter().position(|r| &r.id == userid).unwrap();
                        let data = number_to_data.remove(index).unwrap();
                        number_to_data.push_front(data);
                        drop(number_to_data);
                        match &mut *session.notify.lock().await {
                            Some(s) => {
                                let userid = userid.clone();
                                let _ = s.send(Message::NewMsg(userid, msg.to_string())).await;
                            }
                            None => (),
                        }
                        return Some(());
                    }
                    _ => return None,
                }
            }
        }
    }
    None
}

fn decode_address(address: &str) -> Option<UserData> {
    let mut address = address.split('@');

    let key = match address.next() {
        Some(s) => s,
        None => return None,
    };
    let key = match base64::decode_config(key, base64::URL_SAFE_NO_PAD) {
        Ok(o) => o,
        Err(_) => return None,
    };
    let key = match ed448_rust::PublicKey::try_from(key.as_slice()) {
        Ok(o) => o,
        Err(_) => return None,
    };

    let hostname = match address.next() {
        Some(s) => s.to_string(),
        None => return None,
    };

    Some(UserData {
        id: key,
        hostname,
        username: RwLock::const_new(None),
        send: Mutex::const_new(None),
        handle: Mutex::const_new(None),
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
