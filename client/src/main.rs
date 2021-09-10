/*
RYOKUCHAT is a P2P chat application.

Copyright (C) 2021 TrendCreate

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
    collections::{HashMap, VecDeque},
    convert::TryFrom,
    future::Future,
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use ed448_rust::PublicKey;
use libtor::{HiddenServiceVersion, Tor, TorAddress, TorFlag};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt, BufStream},
    net::TcpListener,
    process::Command,
};

struct SessionData<'a>(Option<SessionDataSome<'a>>);

impl<'a> Deref for SessionData<'a> {
    type Target = SessionDataSome<'a>;

    fn deref(&self) -> &Self::Target {
        match &self.0 {
            Some(s) => s,
            None => unsafe { std::hint::unreachable_unchecked() },
        }
    }
}

impl<'a> DerefMut for SessionData<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.0 {
            Some(s) => s,
            None => unsafe { std::hint::unreachable_unchecked() },
        }
    }
}

// (Address, Name)
#[derive(serde::Serialize, serde::Deserialize)]
struct UserDatas(Vec<(String, Option<String>)>);

struct SessionDataSome<'a> {
    myaddress: String,
    myprivkey: ed448_rust::PrivateKey,
    address_to_data: HashMap<&'a PublicKey, Arc<UserData>>,
    number_to_data: VecDeque<Arc<UserData>>,
}

struct UserData {
    hostname: String,
    username: Option<String>,
    key: PublicKey,
}

static DATA: tokio::sync::RwLock<SessionData> = tokio::sync::RwLock::const_new(SessionData(None));

#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("RYOKUCHAT Copyright (C) 2021 TrendCreate");
    println!("This program comes with ABSOLUTELY NO WARRANTY; for details watch lines 589-619 of the LICENSE file.");
    println!("This is free software, and you are welcome to redistribute it");
    println!("under certain conditions; watch lines 195-341 of the LICENSE file for details.");
    println!();

    init().await.unwrap();
    mainmenu().await;
    Ok(())
}

async fn init() -> Result<(), Box<dyn std::error::Error>> {
    let mut home = dirs::home_dir().unwrap();
    home.push(".config");
    home.push("RYOKUCHAT");
    home.push("tor");
    let _ = fs::create_dir_all(&home).await;
    home.pop();

    home.push("DO_NOT_SEND_TO_OTHER_PEOPLE_secretkey.ykr");
    let mut secretkey: [u8; 57] = [0; 57];

    try_open_read(&home, |mut f| async move {
        println!("Initial setting...");
        f.write_all(ed448_rust::PrivateKey::new(&mut rand::rngs::OsRng).as_bytes())
            .await?;
        Ok(())
    })
    .await?
    .read_exact(&mut secretkey)
    .await?;
    let secretkey = ed448_rust::PrivateKey::try_from(&secretkey)?;
    let publickey = ed448_rust::PublicKey::try_from(&secretkey)?;
    home.pop();

    #[cfg(not(target_os = "windows"))]
    Command::new("chmod")
        .arg("-R")
        .arg("700")
        .arg(home.to_str().unwrap())
        .spawn()?
        .wait()
        .await?;

    home.push("tor");

    Tor::new()
        .flag(TorFlag::Quiet())
        .flag(TorFlag::ExcludeNodes(vec!["SlowServer".to_string()].into()))
        .flag(TorFlag::StrictNodes(true.into()))
        .flag(TorFlag::SocksPortAddress(
            TorAddress::AddressPort("[::1]".to_string(), 4546),
            None.into(),
            None.into(),
        ))
        .flag(TorFlag::HiddenServiceDir(
            home.to_str().unwrap().to_string(),
        ))
        .flag(TorFlag::HiddenServiceVersion(HiddenServiceVersion::V3))
        .flag(TorFlag::HiddenServicePort(
            TorAddress::Port(4545),
            Some(TorAddress::AddressPort("[::1]".to_string(), 4545)).into(),
        ))
        .start_background();

    home.pop();
    home.push("AddressBook.ron");
    let mut addressbook = String::new();
    try_open_read(&home, |mut f| async move {
        f.write_all(ron::to_string(&UserDatas(Vec::new()))?.as_bytes())
            .await?;
        Ok(())
    })
    .await?
    .read_to_string(&mut addressbook)
    .await?;
    let addressbook: VecDeque<Arc<UserData>> = ron::from_str::<UserDatas>(&addressbook)?
        .0
        .into_iter()
        .map(|a| {
            let mut address = a.0.split('@');
            Arc::new(UserData {
                key: ed448_rust::PublicKey::try_from(
                    base64::decode_config(address.next().unwrap(), base64::URL_SAFE_NO_PAD)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap(),
                hostname: address.next().unwrap().to_string(),
                username: a.1,
            })
        })
        .collect();

    *DATA.write().await = SessionData(Some(SessionDataSome {
        myprivkey: secretkey,
        myaddress: {
            home.pop();
            home.push("tor");
            home.push("hostname");
            let mut userid =
                base64::encode_config(publickey.as_bytes().unwrap(), base64::URL_SAFE_NO_PAD);
            userid.push('@');
            let mut hostname = String::new();
            loop {
                if let Ok(mut o) = fs::File::open(&home).await {
                    o.read_to_string(&mut hostname).await?;
                    if hostname.trim().ends_with(".onion") {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            userid.push_str(hostname.trim());
            userid
        },
        address_to_data: {
            let mut data = HashMap::new();
            for i in &addressbook {
                data.insert(
                    unsafe { std::mem::transmute::<&PublicKey, &PublicKey>(&i.key) },
                    Arc::clone(i),
                );
            }
            data
        },
        number_to_data: addressbook,
    }));
    Ok(())
}

async fn mainmenu() -> ! {
    let listen = TcpListener::bind("[::1]:4545").await.unwrap();
    tokio::spawn(async move {
        loop {
            let _ = match listen.accept().await {
                Ok((o, _)) => tokio::spawn(async move {
                    let stream = BufStream::new(o);
                }),
                Err(_) => continue,
            };
        }
    });
    let data = DATA.read().await;
    println!("Your address is: {}", &data.myaddress);
    loop {}
    // loop {
    //     match tokio_socks::tcp::Socks5Stream::connect(
    //         "[::1]:4546",
    //         "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion:80",
    //     )
    //     .await
    //     {
    //         Ok(_) => {
    //             println!("接続成功!");
    //             break;
    //         }
    //         Err(e) => {
    //             eprintln!("{}", e);
    //             tokio::time::sleep(Duration::from_secs(1)).await;
    //         }
    //     }
    // }
}

async fn try_open_read<
    F: Fn(fs::File) -> R,
    R: Future<Output = Result<(), Box<dyn std::error::Error>>>,
>(
    path: &std::path::Path,
    initfn: F,
) -> Result<fs::File, Box<dyn std::error::Error>> {
    match fs::File::open(&path).await {
        Ok(o) => Ok(o),
        Err(_) => match fs::File::create(&path).await {
            Ok(o) => {
                initfn(o).await?;
                Ok(fs::File::open(&path).await?)
            }
            Err(_) => panic!("Could not open and create {:?}", path),
        },
    }
}
