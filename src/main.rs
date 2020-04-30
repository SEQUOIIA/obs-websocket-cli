use tungstenite::Message;
use serde::{Serialize, Deserialize};
use sha2::Digest;
use std::io::Write;

fn main() {
    let (mut socket, response) = tungstenite::connect(url::Url::parse("ws://pyra.clausen:4444").unwrap()).expect("Unable to connect");

    let get_auth_required_req = GetAuthRequiredRequest::new();
    socket.write_message(Message::Text(serde_json::to_string(&get_auth_required_req).unwrap())).unwrap();

    loop {
        let msg = socket.read_message().expect("Error reading message");
        println!("Received: {}", msg);
        let response : Response = serde_json::from_str(msg.clone().into_text().unwrap().as_str()).unwrap();
        match response.message_id.as_ref() {
            "GetAuthRequired" => {
                let gar_response : GetAuthRequiredResponse = serde_json::from_str(msg.clone().into_text().unwrap().as_str()).unwrap();
                println!("{:?}", gar_response);

                let pass_and_salt = format!("{}{}", "Y@bHYSPGDtr$5Q8!TiXD%#v9$5PG8T69BFyCmSonxd$yG72VXAnuCJ2vzc!hBAQu", gar_response.salt.unwrap());
                let mut hasher = sha2::Sha256::new();
                hasher.input(&pass_and_salt);
                let secret_hash = hasher.result();
                let secret = base64::encode(secret_hash);

                let auth_response_string = format!("{}{}", &secret, gar_response.challenge.unwrap());
                hasher = sha2::Sha256::new();
                hasher.input(&auth_response_string);
                let auth_response_hash = hasher.result();
                let auth_response = base64::encode(auth_response_hash);

                let mut auth_req = AuthenticateRequest::new();
                auth_req.auth = Some(auth_response);
                socket.write_message(Message::Text(serde_json::to_string(&auth_req).unwrap())).unwrap();
            },
            "Authenticate" => {
                if response.status.unwrap().contains("ok") {
                    let version_req = GetVersionRequest::new();
                    socket.write_message(Message::Text(serde_json::to_string(&version_req).unwrap())).unwrap();
                }
            }
            _ => {}
        };
    }
}

macro_rules! impl_request {
    ($message_id:literal
    $json_convention:literal
    struct $name:ident {
        $($visib:vis $field_name:ident: $field_type:ty,)*
    }) => {
        #[derive(Serialize, Deserialize, Debug)]
        #[serde(rename_all = $json_convention)]
        struct $name {
            #[serde(rename = "request-type")]
            pub request_type : String,
            #[serde(rename = "message-id")]
            pub message_id : String,
            $($visib $field_name: Option<$field_type>,)*
        }

        impl $name {
            pub fn get_message_id(&self) -> String {
                return $message_id.to_owned()
            }

            pub fn new() -> Self {
                Self {
                    request_type: $message_id.to_owned(),
                    message_id: $message_id.to_owned(),
                    $($field_name: None,)*
                }
            }
        }
    }
}

macro_rules! impl_response {
    ($json_convention:literal
    struct $name: ident {
        $($visib:vis $field_name:ident: $field_type:ty,)*
    }) => {
        #[derive(Serialize, Deserialize, Debug)]
        #[serde(rename_all = $json_convention)]
        struct $name {
            #[serde(rename = "message-id")]
            pub message_id : String,
            pub status : Option<String>,
            pub error : Option<String>,
            $($visib $field_name: Option<$field_type>,)*
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Request {
    #[serde(rename = "request-type")]
    pub request_type : String,
    #[serde(rename = "message-id")]
    pub message_id : String
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    #[serde(rename = "message-id")]
    pub message_id : String,
    pub status : Option<String>,
    pub error : Option<String>
}

impl_request! {
    "GetAuthRequired"
    "snake_case"
    struct GetAuthRequiredRequest {

    }
}

impl_response! {
    "camelCase"
    struct GetAuthRequiredResponse {
        pub auth_required : bool,
        pub challenge : String,
        pub salt : String,
    }
}

impl_request! {
    "Authenticate"
    "camelCase"
    struct AuthenticateRequest {
        pub auth : String,
    }
}


impl_request! {
    "GetVersion"
    "snake_case"
    struct GetVersionRequest {

    }
}

impl_response! {
    "kebab-case"
    struct GetVersionResponse {
        pub version : f64,
        pub obs_websocket_version : String,
        pub obs_studio_version : String,
        pub available_requests : String,
        pub supported_image_export_formats : String,
    }
}