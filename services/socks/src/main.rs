extern crate hyper;
extern crate urlparse;

use std::sync::{Arc, Mutex};

use std::io::Read;

use std::collections::HashMap;

use hyper::server::{Handler, Server, Request, Response};
use hyper::status::StatusCode;

use urlparse::urlparse;
use urlparse::GetQuery;  // Trait


struct Context {
    stor : Mutex<HashMap<String, String>>,
}

impl Context {
    pub fn new() -> Context {
        let mut context = Context{stor : Mutex::new(HashMap::new())};
        context
    }
}

impl Handler for Context {
    fn handle(&self, mut req: Request, mut res: Response) {
        // self.sender.lock().unwrap().send("start").unwrap();
        // println!("{}", req.uri);
        let url = urlparse(req.uri.to_string());
        let query = url.get_parsed_query().unwrap();

        println!("{}", url.path);

        if url.path == "/search" {
            let text = query.get_first_from_str("text").unwrap();
            let stor = self.stor.lock().unwrap();
            // let status: &mut StatusCode = res.status_mut();
            let mut data: String;

            match stor.get(text.as_str()) {
                Some(value) => { res.send(value.as_bytes()).unwrap() },
                None => *res.status_mut() = StatusCode::NotFound
            }
        }

        if url.path == "/set" {
            let mut stor = self.stor.lock().unwrap();
            let mut data = String::new();
            let text = query.get_first_from_str("text").unwrap();
            req.read_to_string(&mut data);
            stor.insert(text, data.clone());
        }
    }

}

fn main() {
    let mut context = Context::new();
    Server::http("127.0.0.1:3000").unwrap()
        .handle(context).unwrap();
}
