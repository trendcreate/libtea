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

use std::{future::Future, io::Cursor};

use byteorder::BigEndian;
use ed448_rust::{PublicKey, SIG_LENGTH};
use rand::Rng;
use tokio::io::AsyncReadExt;
use tokio::{
    fs,
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};

use crate::inside::structs::ErrMsg;
use crate::{
    consts::MAXMSGLEN,
    inside::structs::{HandleWrapper, MessageForNetwork, UserDataRaw, UserDataTemp},
    Message, RYOKUCHATSession, UserData,
};

pub async fn process_message<
    T: 'static + AsyncRead + AsyncWrite + std::marker::Send + std::marker::Sync + std::marker::Unpin,
>(
    session: &RYOKUCHATSession,
    userid: PublicKey,
    stream: T,
) {
    trace!("process_message() is called.");
    defer!(trace!("reterning from process_message()"));

    let session = unsafe { std::mem::transmute::<&RYOKUCHATSession, &RYOKUCHATSession>(session) };
    let (mut read, write) = tokio::io::split(stream);

    session.user_data_temp.write().await.insert(
        userid.as_byte(),
        UserDataTemp {
            send: Mutex::new(Box::new(write)),
            handle: HandleWrapper(tokio::spawn(async move {
                defer!(warn!("connection closed"));
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

async fn process_message2<
    T: AsyncRead + std::marker::Send + std::marker::Sync + std::marker::Unpin,
>(
    session: &RYOKUCHATSession,
    userid: &PublicKey,
    read: &mut T,
) -> Option<()> {
    trace!("process_message2() is called.");
    defer!(trace!("reterning from process_message2()"));

    // メッセージのサイズを受信
    let mut len = [0; 8];
    read.read_exact(&mut len).await.ok()?;
    debug!("new message come");

    // 受け取ったデータを処理
    let mut len = Cursor::new(len);
    let len = byteorder::ReadBytesExt::read_u64::<BigEndian>(&mut len)
        .err_exec(|e| error!("{}", e))
        .ok()?;
    let len: usize = TryFrom::try_from(len)
        .err_exec(|_| error!("32bit CPUs are not officially supported"))
        .ok()?;
    debug!("new message's size is {} byte", len);

    // メッセージのサイズが最大値を超えていたらエラー
    if len >= MAXMSGLEN {
        error!("message's size must be under 126000");
        return None;
    }

    // メッセージを受信(lenバイトはメッセージ本体､SIG_LENGTHバイトは署名)
    let mut msg = vec![0; len + SIG_LENGTH];
    read.read_exact(&mut msg).await.ok()?;
    // 署名を検証
    userid
        .verify(&msg[..len], &msg[len..], None)
        .err_exec(|e| error!("{}", e))
        .ok()?;
    // メッセージをデシリアライズ
    let msg: MessageForNetwork = bincode::deserialize(&msg[..len])
        .err_exec(|_| error!("wrong message format"))
        .ok()?;

    match msg {
        MessageForNetwork::DirectMsg(msg) => {
            // stub: メッセージ履歴の保存を実装
            if msg.is_empty() {
                error!("empty message is not allowed");
                return None;
            }
            session.new_lastupdate(userid).await?;

            match &mut *session.notify.lock().await {
                Some(s) => {
                    let _ = s.send(Message::DirectMsg(userid.clone(), msg)).await;
                }
                None => {
                    warn!("session.notify is not set");
                }
            }

            Some(())
        }
    }
}

pub fn decode_address(address: &str) -> Option<UserData> {
    trace!("RYOKUCHATSession::decode_address() is called");
    defer!(trace!("returning from RYOKUCHATSession::decode_address()"));

    let address = address.trim();
    debug!("address is {}", address);

    let mut address = address.split('@');

    let key = address
        .next()
        .err_exec(|_| error!("something went wrong"))?;
    let key = base64::decode_config(key, base64::URL_SAFE_NO_PAD)
        .err_exec(|e| error!("{}", e))
        .ok()?;

    let hostname = address
        .next()
        .err_exec(|_| error!("wrong format"))?
        .to_string();

    UserDataRaw {
        id: key,
        hostname,
        username: None,
    }
    .to_userdata()
}

pub fn greeting_auth(auth: &[u8]) -> Option<[u8; 16]> {
    trace!("greeting_auth() is called");
    defer!(trace!("returning from greeting_auth()"));

    let mut auth = Cursor::new(auth);
    let auth = byteorder::ReadBytesExt::read_u128::<BigEndian>(&mut auth).ok()?;
    debug!("authentication message is {}", auth);

    Some(auth.to_le_bytes())
}

pub async fn try_open_read<
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

    panic!("could not open and create {:?}", path);
}

pub fn passwd_gen() -> String {
    let mut passwd = String::with_capacity(32);
    for _ in 0..32 {
        let mut random: u32 = rand::rngs::OsRng.gen_range(0..62);
        random = if random < 10 {
            rand::rngs::OsRng.gen_range(48..=57)
        } else if random < 36 {
            rand::rngs::OsRng.gen_range(65..=90)
        } else {
            rand::rngs::OsRng.gen_range(97..=122)
        };
        unsafe {
            passwd.push(std::mem::transmute(random));
        }
    }
    debug!("generated password is {}", &passwd);
    passwd
}
