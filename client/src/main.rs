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

use std::{convert::TryFrom, thread::sleep_ms};

use libtor::{HiddenServiceVersion, Tor, TorAddress, TorFlag};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

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
    loop {
        match tokio_socks::tcp::Socks5Stream::connect(
            "[::1]:4546",
            "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion:80",
        )
        .await
        {
            Ok(_) => {
                println!("接続成功!");
                break;
            }
            Err(e) => {
                eprintln!("{}", e);
                sleep_ms(1000);
            }
        }
    }
    Ok(())
}
