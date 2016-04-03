use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use std::io::BufReader;
use std::io::BufRead;
use std::sync::{Arc, Mutex};

use std::collections::HashMap;


struct Context {
    stor : Mutex<HashMap<String, String>>,
    handlers : HashMap<String, fn(Vec<&str>, Arc<Context>) -> Result<String, String> >
}

impl Context {
    pub fn new() -> Context {
        let mut context = Context{stor : Mutex::new(HashMap::new()), handlers: HashMap::new()};
        context.handlers.insert("GET".to_string(), get);
        context.handlers.insert("PUT".to_string(), put);
        context
    }
}

fn get(args: Vec<&str>, context: Arc<Context>) -> Result<String, String> {
    println!("GET!");
    if args.len() != 2 {
        return Err("Not enougth args!".to_string());
    }

    let key = args[1];
    let stor = context.stor.lock().unwrap();
    match stor.get(key) {
        Some(value) => {return Ok((value.clone()))},
        None => return Err(("NOT FOUND".to_string())),
    }

    Ok((String::new()))
}

fn put(args: Vec<&str>, context: Arc<Context>) -> Result<String, String> {
    println!("PUT!");
    if args.len() != 3 {
        return Err("Not enougth args!".to_string());
    }

    let key = args[1].to_string();
    let value = args[2].to_string();
    let mut stor = context.stor.lock().unwrap();
    stor.insert(key, value.clone());

    Ok((value))
}


fn handle_client(mut stream: TcpStream, context: Arc<Context>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut buf = String::new();
    loop {
        // let context = context.clone();
        buf.clear();
        match reader.read_line(&mut buf) {
            Ok(v) => {
                let line = buf.trim();
                // stream.write(line.as_bytes());
                println!("Line: {:?}", line);
                // if line.len() == 0 {
                //     break;
                // }

                let mut args: Vec<&str> = line.split("\t").collect();
                let handler_name = args[0];
                println!("Handler name: {:?}", handler_name);
                match context.handlers.get(&handler_name.to_string()) {
                    Some(handler) => {
                        match handler(args, context.clone()) {
                            Ok(reply) => {
                                stream.write(b"[OK] ");
                                stream.write(reply.as_bytes());
                                stream.write(b"\n");
                            },
                            Err(e) => {
                                stream.write(b"[ERR] ");
                                stream.write(e.as_bytes());
                                stream.write(b"\n");
                            }
                        };
                    },
                    None => { stream.write(b"Unkwon command!\n"); }
                }
            },
            Err(e) => {
                break;
            }

        }
    }
    // Ok(())
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:9123").unwrap();
    println!("listening started, ready to accept");
    let mut context = Arc::new(Context::new());
    for stream in listener.incoming() {
        let context = context.clone();
        thread::spawn(move || {
            let mut stream = stream.unwrap();
            handle_client(stream, context);
        });
    }
}
