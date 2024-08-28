use lazy_static::lazy_static;
use serde_json::json;

lazy_static! {
    pub static ref USER_DATA: serde_json::Value = json!({
        "given_name": "John",
        "family_name": "Doe",
        "birthdate": "1990-01-01",
        "email": "johndoe@example.com",
        "address": {
            "street_address": "123 Main St",
            "locality": "Anytown",
            "region": "State",
            "country": "US"
        }
    });
}
