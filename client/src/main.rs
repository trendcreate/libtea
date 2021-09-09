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
    convert::TryFrom,
    ops::{Deref, DerefMut},
    time::Duration,
};

use libtor::{HiddenServiceVersion, Tor, TorAddress, TorFlag};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt, BufStream},
    net::TcpListener,
    process::Command,
};

struct SessionData(Option<SessionDataSome>);

impl Deref for SessionData {
    type Target = SessionDataSome;

    fn deref(&self) -> &Self::Target {
        match &self.0 {
            Some(s) => s,
            None => unsafe { std::hint::unreachable_unchecked() },
        }
    }
}

impl DerefMut for SessionData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.0 {
            Some(s) => s,
            None => unsafe { std::hint::unreachable_unchecked() },
        }
    }
}

struct SessionDataSome {
    myaddress: String,
    myprivkey: ed448_rust::PrivateKey,
    address_book: Vec<String>,
}

static DATA: tokio::sync::RwLock<SessionData> = tokio::sync::RwLock::const_new(SessionData(None));

#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("RYOKUCHAT Copyright (C) 2021 TrendCreate");
    println!("This program comes with ABSOLUTELY NO WARRANTY; for details watch lines 589-619 of the LICENSE file.");
    println!("This is free software, and you are welcome to redistribute it");
    println!("under certain conditions; watch lines 195-341 of the LICENSE file for details.");
    println!();

    let mut home = dirs::home_dir().unwrap();
    home.push(".config");
    home.push("RYOKUCHAT");
    home.push("tor");
    let _ = fs::create_dir_all(&home).await;
    home.pop();

    home.push("DO_NOT_SEND_TO_OTHER_PEOPLE_secretkey.ykr");
    let mut secretkey: [u8; 57] = [0; 57];
    match fs::File::open(&home).await {
        Ok(o) => o,
        Err(_) => match fs::File::create(&home).await {
            Ok(mut o) => {
                println!("Initial setting...");
                let privkey = ed448_rust::PrivateKey::new(&mut rand::rngs::OsRng);
                o.write_all(privkey.as_bytes()).await?;
                drop(o);
                fs::File::open(&home).await?
            },
            Err(_) => panic!("Could not open and create ~/.config/RYOKUCHAT/DO_NOT_SEND_TO_OTHER_PEOPLE_secretkey.ykr")
        }
    }.read_exact(&mut secretkey).await?;
    let secretkey = ed448_rust::PrivateKey::try_from(&secretkey).unwrap();
    let publickey = ed448_rust::PublicKey::try_from(&secretkey).unwrap();
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

    *DATA.write().await = SessionData(Some(SessionDataSome {
        myprivkey: secretkey,
        address_book: Vec::new(), //stub
        myaddress: {
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
    }));
    mainmenu().await;
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
    loop {
        let data = DATA.read().await;
        println!("Your address is: {}", &data.myaddress);
    }
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
