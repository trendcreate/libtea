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

use std::{fs::File, io::Write};

use ed448_rust::{PrivateKey, PublicKey};
use rand_core::OsRng;

fn main() {
    println!("RYOKUCHAT Copyright (C) 2021 TrendCreate");
    println!("This program comes with ABSOLUTELY NO WARRANTY; for details watch lines 589-619 of the LICENSE file.");
    println!("This is free software, and you are welcome to redistribute it");
    println!("under certain conditions; watch lines 195-341 of the LICENSE file for details.");
    println!();

    let privkey = PrivateKey::new(&mut OsRng);
    let pubkey = PublicKey::from(&privkey);
    let mut privfile = File::create("./ed448_key_secret").unwrap();
    let mut pubfile = File::create("./ed448_key_public").unwrap();
    privfile.write_all(privkey.as_bytes()).unwrap();
    pubfile.write_all(&pubkey.as_bytes().unwrap()).unwrap();
}
