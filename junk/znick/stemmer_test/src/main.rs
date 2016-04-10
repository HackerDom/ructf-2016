extern crate stemmer;

use std::io::prelude::*;
use std::io;
use stemmer::Stemmer;



fn main() {
    let stdin = io::stdin();
    let mut stemmer = Stemmer::new("english").unwrap();
    for l in stdin.lock().lines() {
        let line = l.unwrap();
        println!("{}", line);

        let words: Vec<&str> = line.split(" ").collect();
        for word in words {
            println!("{}", stemmer.stem(word));
        }

    }
    println!("Hello, world!");
}
