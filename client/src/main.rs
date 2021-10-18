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

// use std::{
//     cell::UnsafeCell,
//     collections::{HashMap, VecDeque},
//     convert::TryFrom,
//     future::Future,
//     ops::{Deref, DerefMut},
//     sync::Arc,
//     time::Duration,
// };

// struct SessionData<'a>(UnsafeCell<Option<SessionDataSome<'a>>>, UnsafeCell<bool>);

// impl<'a> Deref for SessionData<'a> {
//     type Target = SessionDataSome<'a>;

//     fn deref(&self) -> &Self::Target {
//         unsafe {
//             match &*self.0.get() {
//                 Some(s) => s,
//                 None => std::hint::unreachable_unchecked(),
//             }
//         }
//     }
// }

// #[allow(clippy::mut_from_ref)]
// impl<'a> SessionData<'a> {
//     unsafe fn set(&'a self) -> &'a mut Option<SessionDataSome> {
//         if *self.1.get() {
//             panic!("errorcode: 1");
//         } else {
//             *self.1.get() = true;
//             &mut *(self.0.get())
//         }
//     }
// }

// unsafe impl<'a> std::marker::Sync for SessionData<'a> {}
// unsafe impl<'a> std::marker::Send for SessionData<'a> {}

// static DATA: SessionData = SessionData(UnsafeCell::new(None), UnsafeCell::new(false));

// #[tokio::main]
// async fn main() -> std::io::Result<()> {
//     println!("RYOKUCHAT Copyright (C) 2021 TrendCreate");
//     println!("This program comes with ABSOLUTELY NO WARRANTY; for details watch lines 589-619 of the LICENSE file.");
//     println!("This is free software, and you are welcome to redistribute it");
//     println!("under certain conditions; watch lines 195-341 of the LICENSE file for details.");
//     println!();

//     let session = libtea::RYOKUCHATSession::new(dirs::home_dir().unwrap(), 4546, 4545).await;

//     Ok(())
// }

// async fn mainmenu() -> ! {
//     let listen = TcpListener::bind("[::1]:4545").await.unwrap();
//     tokio::spawn(async move {
//         loop {
//             let _ = match listen.accept().await {
//                 Ok((o, _)) => tokio::spawn(async move {
//                     let stream = BufStream::new(o);
//                 }),
//                 Err(_) => continue,
//             };
//         }
//     });
//     let mut stdin = BufReader::new(tokio::io::stdin());
//     let mut input = String::new();
//     loop {
//         println!("Your address is: {}", &DATA.myaddress);
//         println!("/help to command list.");
//         println!("Input index of friend or command.");
//         let mut temp: usize = 0;
//         let mut data = DATA.number_to_data.write().await;
//         for i in &*data {
//             match &*i.username.read().await {
//                 Some(s) => println!("{}. {}", temp, s),
//                 None => println!("no_name ({})", i.hostname),
//             }
//             temp += 1;
//         }

//         let mut stdout = tokio::io::stdout();
//         stdout.write_all("RYOKUCHAT> ".as_bytes()).await.unwrap();
//         stdout.flush().await.unwrap();
//         drop(stdout);

//         stdin.read_line(&mut input).await.unwrap();
//         match command_execute(&input).await {
//             Some(s) => {
//                 let _ = s.await;
//             }
//             None => {}
//         }
//         println!();
//     }
//     // loop {
//     //     match tokio_socks::tcp::Socks5Stream::connect(
//     //         "[::1]:4546",
//     //         "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion:80",
//     //     )
//     //     .await
//     //     {
//     //         Ok(_) => {
//     //             println!("接続成功!");
//     //             break;
//     //         }
//     //         Err(e) => {
//     //             eprintln!("{}", e);
//     //             tokio::time::sleep(Duration::from_secs(1)).await;
//     //         }
//     //     }
//     // }
// }

// #[allow(clippy::manual_strip)]
// async fn command_execute(
//     command: &str,
// ) -> Option<std::pin::Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error>>>>>> {
//     let command = command.trim();
//     if command.starts_with('/') {
//         if command.len() > 1 {
//             let mut command = command[1..].split(' ');
//             match command.next().unwrap() {
//                 "add" => {
//                     let arg = match command.next() {
//                         Some(s) => s,
//                         None => {
//                             println!("Requires an argument.");
//                             return None;
//                         }
//                     }
//                     .to_string();
//                     Some(Box::pin(async move {
//                         if let Some(s) = decode_address(&arg) {
//                             let s = Arc::new(s);
//                             DATA.number_to_data.write().await.push_front(Arc::clone(&s));
//                             unsafe {
//                                 DATA.address_to_data.write().await.insert(
//                                     std::mem::transmute::<&PublicKey, &PublicKey>(&s.key),
//                                     Arc::clone(&s),
//                                 );
//                             }
//                             println!("Command succeeded.");
//                         } else {
//                             println!("Wrong argument format.");
//                         }
//                         Ok(())
//                     }))
//                 }
//                 _ => None,
//             }
//         } else {
//             None
//         }
//     } else {
//         None
//     }
// }

// fn decode_address(address: &str) -> Option<UserData> {
//     let mut address = address.split('@');
//     Some(UserData {
//         key: match ed448_rust::PublicKey::try_from(
//             match base64::decode_config(
//                 match address.next() {
//                     Some(s) => s,
//                     None => return None,
//                 },
//                 base64::URL_SAFE_NO_PAD,
//             ) {
//                 Ok(o) => o,
//                 Err(_) => return None,
//             }
//             .as_slice(),
//         ) {
//             Ok(o) => o,
//             Err(_) => return None,
//         },
//         hostname: match address.next() {
//             Some(s) => s.to_string(),
//             None => return None,
//         },
//         username: RwLock::const_new(None),
//     })
// }

// async fn try_open_read<
//     F: Fn(fs::File) -> R,
//     R: Future<Output = Result<(), Box<dyn std::error::Error>>>,
// >(
//     path: &std::path::Path,
//     initfn: F,
// ) -> Result<fs::File, Box<dyn std::error::Error>> {
//     match fs::File::open(&path).await {
//         Ok(o) => Ok(o),
//         Err(_) => match fs::File::create(&path).await {
//             Ok(o) => {
//                 initfn(o).await?;
//                 Ok(fs::File::open(&path).await?)
//             }
//             Err(_) => panic!("Could not open and create {:?}", path),
//         },
//     }
// }
fn main() {
    println!("hello world!");
}
