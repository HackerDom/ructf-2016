extern crate hyper;
extern crate urlparse;
extern crate stemmer;
extern crate rustc_serialize as serialize;
extern crate regex;

use std::sync::{Arc, Mutex};

use std::io::Read;
use std::io::Write;

use std::collections::HashMap;
use std::collections::HashSet;

use hyper::server::{Handler, Server, Request, Response};
use hyper::status::StatusCode;

use urlparse::urlparse;
use urlparse::GetQuery;  // Trait

use stemmer::Stemmer;

use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::OpenOptions;

use serialize::base64::{self, ToBase64, FromBase64};

use regex::Regex;

mod st;

struct Context {
    docs : Mutex<Vec<String>>,
    index : Mutex<HashMap<String, Vec<usize>>>,
    logfile : String,
    owner_re : Regex,
}

impl Context {
    pub fn new() -> Context {
        let mut context = Context{docs : Mutex::new(Vec::new()),
                                  index : Mutex::new(HashMap::new()),
                                  logfile : "query.log".to_string(),
                                  owner_re : Regex::new(r"^\w{4}-\w{4}-\w{4}$").unwrap() };
        context.read_from_log();
        context
    }

    pub fn read_from_log(&self) {
        match File::open(self.logfile.clone()) {
            Ok(f) => {
                let mut reader = BufReader::new(f);

                for line in reader.lines() {
                    let line = line.unwrap();
                    let parts: Vec<&str> = line.split("\t").collect();
                    let body = parts[2].from_base64().unwrap();
                    self.index(String::from_utf8(body).unwrap(), parts[0].to_string(), parts[1].to_string());
                }
            },
            Err(e) => {}
        }
    }

    pub fn index(&self, body: String, id: String, owner: String) {
        let mut doc_id = 0;
        {
            let mut docs = self.docs.lock().unwrap();
            docs.push(id);
            doc_id = docs.len() - 1;
        }

        {
            let mut index = self.index.lock().unwrap();
            let mut stemmer = Stemmer::new("english").unwrap();
            for word in body.to_lowercase().split_whitespace() {
                let stem = stemmer.stem(word);
                if !index.contains_key(&stem) {
                    index.insert(stem.clone(), Vec::new());
                }

                if let Some(docs) = index.get_mut(&stem) {
                    (*docs).push(doc_id);
                }
            }

            let owner_word: String = "#owner=".to_string() + &owner;
            if !index.contains_key(&owner_word) {
                index.insert(owner_word.clone(), Vec::new());
            }

            if let Some(docs) = index.get_mut(&owner_word) {
                (*docs).push(doc_id);
            }
        }
    }

    pub fn search(&self, text:String) -> Vec<String> {
        let text = text.to_lowercase();
        let mut res: Vec<String> = Vec::new();
        let mut doc_ids: HashSet<usize> = HashSet::new();

        {
            let mut index = self.index.lock().unwrap();
            let mut stemmer = Stemmer::new("english").unwrap();
            for word in text.split_whitespace() {
                let stem = stemmer.stem(word);
                match index.get(&stem) {
                    Some(ids) => {
                        let word_doc_ids: HashSet<_> = ids.iter().cloned().collect();
                        if doc_ids.is_empty() {
                            doc_ids = word_doc_ids;
                        } else {
                            doc_ids = doc_ids.intersection(&word_doc_ids).cloned().collect();
                        }

                    }
                    None => { println!("NONE"); }
                }
            }
        }

        {
            let mut docs = self.docs.lock().unwrap();
            for doc_id in doc_ids {
                res.push(docs[doc_id].clone());
            }
        }

        res
    }

}

impl Handler for Context {
    fn handle(&self, mut req: Request, mut res: Response) {
        // self.sender.lock().unwrap().send("start").unwrap();
        // println!("{}", req.uri);

        let url = urlparse(req.uri.to_string());
        if url.path == "/" {
            let mut res = res.start().unwrap();
            res.write_all(st::INDEX.as_bytes());
            return;
        }

        let query = url.get_parsed_query().unwrap();
        let mut text = query.get_first_from_str("text").unwrap();
        let owner = query.get_first_from_str("owner").unwrap();

        if (!self.owner_re.is_match(owner.as_str())) {
            *res.status_mut() = StatusCode::Forbidden;
            return;
        }

        println!("{}", url.path);

        if url.path == "/search" {
            let mut request: String = "#owner=".to_string() + &owner;
            request.push_str(" ");
            request.push_str(text.as_str());
            text = request;
            println!("TEXT:{:?}", text);

            let mut data: String;
            let mut res = res.start().unwrap();

            for id in self.search(text) {
                println!("{}", id);
                res.write_all(id.as_bytes()).unwrap();
                res.write_all(b"\n").unwrap();
            }

            return;
        }

        if url.path == "/set" {
            let mut data = String::new();
            req.read_to_string(&mut data);

            {
                let mut file =
                    OpenOptions::new()
                    .write(true)
                    .append(true)
                    .create(true)
                    .open("query.log")
                    .unwrap();

                writeln!(file, "{}\t{}\t{}", text.clone(), owner.clone(), data.as_bytes().to_base64(base64::STANDARD));
            }

            self.index(data.clone(), text.clone(), owner);
            return;
        }

        *res.status_mut() = StatusCode::NotFound;
    }
}

fn main() {
    let mut context = Context::new();
    Server::http("0.0.0.0:3030").unwrap()
        .handle(context).unwrap();
}
