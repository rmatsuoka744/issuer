use lazy_static::lazy_static;
use serde_json::json;

lazy_static! {
    pub static ref USER_DATA: serde_json::Value = json!({
      "vct": "https://credentials.example.com/identity_credential",
      "given_name": "John",
      "family_name": "Doe",
      "email": "johndoe@example.com",
      "phone_number": "+1-202-555-0101",
      "address": {
        "street_address": "123 Main St",
        "locality": "Anytown",
        "region": "Anystate",
        "country": "US"
      },
      "birthdate": "1940-01-01",
      "is_over_18": true,
      "is_over_21": true,
      "is_over_65": true
    });
}

lazy_static! {
    pub static ref PATIENT_DATA: serde_json::Value = json!({
      "vct": "https://credentials.example.com/identity_credential",
      "patient_id": "test_id"
    });
}
