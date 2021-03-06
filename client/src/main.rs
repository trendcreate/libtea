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

use libtea::Message;
use rand::Rng;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() {
    env_logger::init();
    println!("RYOKUCHAT Copyright (C) 2021 TrendCreate");
    println!("RYOKUCHAT Copyright (C) 2021 WinLinux1028");
    println!("RYOKUCHAT Copyright (C) 2021 TRENDcreate");
    println!("This program comes with ABSOLUTELY NO WARRANTY; for details watch lines 589-619 of the LICENSE file.");
    println!("This is free software, and you are welcome to redistribute it");
    println!("under certain conditions; watch lines 195-341 of the LICENSE file for details.");
    println!();

    main2().await;
}

async fn main2() {
    let mut data_dir = dirs::home_dir().unwrap();
    data_dir.push(".config");
    data_dir.push("RYOKUCHAT");

    println!("This client is developed debugging libtea.");
    println!("Select debug mode:");
    println!("1: As client 1");
    println!("2: As client 2");
    let port;
    loop {
        let mut stdout = tokio::io::stdout();
        stdout.write_all("> ".as_bytes()).await.unwrap();
        stdout.flush().await.unwrap();
        drop(stdout);
        let mut stdin = BufReader::new(tokio::io::stdin());
        let mut input = String::new();
        stdin.read_line(&mut input).await.unwrap();
        let input = input.trim();

        match input {
            "1" => {
                data_dir.push("client1");
                port = 4545;
            }
            "2" => {
                data_dir.push("client2");
                port = 1919;
            }
            _ => continue,
        }
        break;
    }

    let session = libtea::RYOKUCHATSession::new(data_dir, port).await;
    let (send, mut receive) = tokio::sync::mpsc::channel(1);
    *session.notify.lock().await = Some(send);

    loop {
        println!("Your address is: {}", &session.myaddress());
        println!("/help to command list.");
        println!("Input index of friend or command.");
        let mut temp: usize = 0;
        let data = session.get_users().await.unwrap();
        for i in &data {
            match &i.username {
                Some(s) => println!("{}. {}", temp, s),
                None => println!("{}. no_name ({})", temp, i.get_address()),
            }
            temp += 1;
        }

        let mut stdout = tokio::io::stdout();
        stdout.write_all("MAINMENU> ".as_bytes()).await.unwrap();
        stdout.flush().await.unwrap();
        drop(stdout);

        let mut stdin = BufReader::new(tokio::io::stdin());
        let mut input = String::new();
        stdin.read_line(&mut input).await.unwrap();
        let input = input.trim();

        let mut command_ok = None;
        if input.starts_with("/help") {
            help().await;
        } else if input.starts_with("/add") {
            command_ok = Some(add(&session, input).await);
        } else if input.starts_with("/del") {
            command_ok = Some(del(&session, &data, input).await);
        } else if input.starts_with("/exit") {
            return;
        } else {
            let index: usize = match input.parse() {
                Ok(o) => o,
                Err(_) => continue,
            };
            chat_session(&session, &data[index], &mut receive).await;
        }
        if let Some(s) = command_ok {
            match s {
                true => println!("Command Successful!"),
                false => println!("Command failed."),
            }
        }
        println!();
    }
}

async fn chat_session(
    session: &libtea::RYOKUCHATSession,
    user: &libtea::UserData,
    receiver: &mut tokio::sync::mpsc::Receiver<Message>,
) {
    let receiver = unsafe {
        std::mem::transmute::<
            &mut tokio::sync::mpsc::Receiver<Message>,
            &mut tokio::sync::mpsc::Receiver<Message>,
        >(receiver)
    };
    let user = unsafe { std::mem::transmute::<&libtea::UserData, &libtea::UserData>(user) };
    let handle = tokio::spawn(async move {
        loop {
            let newmsg = match receiver.recv().await {
                Some(Message::DirectMsg(a, b)) => {
                    if a.as_byte() == user.id.as_byte() {
                        b
                    } else {
                        continue;
                    }
                }
                None => continue,
            };
            println!("> {}", newmsg);
        }
    });
    loop {
        let mut stdout = tokio::io::stdout();
        stdout.write_all("CHAT> ".as_bytes()).await.unwrap();
        stdout.flush().await.unwrap();
        let mut stdin = BufReader::new(tokio::io::stdin());
        let mut input = String::new();
        stdin.read_line(&mut input).await.unwrap();
        let input = input.trim();

        if input.starts_with("/help") {
            help().await;
        } else if input.starts_with("/add") || input.starts_with("/del") {
            println!("Can't use this command now.");
        } else if input.starts_with("/exit") {
            handle.abort();
            return;
        }

        if suicide_check(input) {
            eprintln!("?????????????????????");
            eprintln!("??????????????????????????????????????????");
            eprintln!("+81 570-064-556");
        }
        if session.send_dm(&user.id, input).await.is_none() {
            println!("Error while sending.");
        }
    }
}

async fn help() {
    println!("/help: Display this message\n/add (address): Add friend to your addressbook.\n/del (index): Delete friend from your addressbook.\n/exit: Exit from this screen.")
}

async fn add(session: &libtea::RYOKUCHATSession, input: &str) -> bool {
    let mut hoge = input.split(' ');
    let _ = hoge.next();
    let address = match hoge.next() {
        Some(s) => s,
        None => return false,
    };

    session.add_user(address).await.is_some()
}

async fn del(session: &libtea::RYOKUCHATSession, data: &[libtea::UserData], input: &str) -> bool {
    let mut hoge = input.split(' ');
    let _ = hoge.next();
    let index: usize = match hoge.next() {
        Some(s) => match s.parse() {
            Ok(o) => o,
            Err(_) => return false,
        },
        None => return false,
    };

    let user = &data[index];
    session.del_user(&user.id).await.is_some()
}

fn suicide_check(msg: &str) -> bool {
    unsafe {
        if WARNED {
            // 1/3
            if 0 < rand::rngs::OsRng.gen_range(0..3) {
                return false;
            }
        }
    }
    for i in NG_WORD {
        if msg.contains(i) {
            unsafe {
                WARNED = true;
            }
            return true;
        }
    }
    false
}

const NG_WORD: [&str; 2] = ["??????", "????????????"];
static mut WARNED: bool = false;
