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
use ed448_rust::PublicKey;
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
    let session = unsafe { std::mem::transmute::<&RYOKUCHATSession, &RYOKUCHATSession>(session) };
    let (mut read, write) = tokio::io::split(stream);

    session.user_data_temp.write().await.insert(
        userid.as_byte(),
        UserDataTemp {
            send: Mutex::new(Box::new(write)),
            handle: HandleWrapper(tokio::spawn(async move {
                defer!(error!("connection closed"));
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
    // メッセージのサイズを受信
    let mut len = [0; 8];
    read.read_exact(&mut len).await.ok()?;
    let mut len = Cursor::new(len);
    let len = byteorder::ReadBytesExt::read_u64::<BigEndian>(&mut len).ok()?;
    let len: usize = TryFrom::try_from(len).ok()?;
    if len < MAXMSGLEN {
        let mut msg = vec![0; len];
        read.read_exact(&mut msg).await.ok()?;
        let msg: MessageForNetwork = bincode::deserialize(&msg).ok()?;
        match msg {
            MessageForNetwork::DirectMsg(msg) => {
                // stub: メッセージ履歴の保存を実装
                if msg.is_empty() {
                    return None;
                }

                session.new_lastupdate(userid).await?;

                match &mut *session.notify.lock().await {
                    Some(s) => {
                        let _ = s.send(Message::DirectMsg(userid.clone(), msg)).await;
                    }
                    None => (),
                }
                return Some(());
            }
        }
    }
    None
}

pub fn decode_address(address: &str) -> Option<UserData> {
    trace!("RYOKUCHATSession::decode_address() is called");
    defer!(trace!("returning from RYOKUCHATSession::decode_address()"));
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

    panic!("Could not open and create {:?}", path);
}
