extern crate mlkem_native_rs;
extern crate rand;

use mlkem_native_rs::{mlkem768_dec, mlkem768_enc, mlkem768_keypair};
use rand::rngs::OsRng;

fn main() {
    let (sk, pk) = mlkem768_keypair(&mut OsRng).unwrap();

    println!("sk: {:?}", sk);
    println!("pk: {:?}", pk);

    let (ct, ss) = mlkem768_enc(&mut OsRng, &pk).unwrap();

    println!("ct: {:?}", ct);
    println!("ss : {:?}", ss);

    let ss2 = mlkem768_dec(&sk, &ct).unwrap();

    assert_eq!(ss, ss2);

    println!("ss2: {:?}", ss2);
}
