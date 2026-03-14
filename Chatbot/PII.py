"""
PII Detection Engine using GLiNER
"""

from gliner import GLiNER

# =========================
# MODEL CONFIG
# =========================
MODEL_PATH = "./models/gretel-gliner/models--gretelai--gretel-gliner-bi-large-v1.0/snapshots/f96d1da43b97bd1846b14a7068a57e1ab15f226e"

# =========================
# PII LABELS
# =========================
PII_LABELS = [
    "medical_record_number",
    "date_of_birth",
    "ssn",
    "date",
    "first_name",
    "email",
    "last_name",
    "customer_id",
    "employee_id",
    "name",
    "street_address",
    "phone_number",
    "ipv4",
    "credit_card_number",
    "license_plate",
    "address",
    "user_name",
    "device_identifier",
    "bank_routing_number",
    "date_time",
    "company_name",
    "unique_identifier",
    "biometric_identifier",
    "account_number",
    "city",
    "certificate_license_number",
    "time",
    "postcode",
    "vehicle_identifier",
    "coordinate",
    "country",
    "api_key",
    "ipv6",
    "password",
    "health_plan_beneficiary_number",
    "national_id",
    "tax_id",
    "url",
    "state",
    "swift_bic",
    "cvv",
    "pin"
]

# =========================
# PLACEHOLDER MAPPING
# =========================
LABEL_PLACEHOLDERS = {
    "medical_record_number": "<MEDICAL_RECORD_NUMBER>",
    "date_of_birth": "<DATE_OF_BIRTH>",
    "ssn": "<SSN>",
    "date": "<DATE>",
    "first_name": "<FIRST_NAME>",
    "email": "<EMAIL>",
    "last_name": "<LAST_NAME>",
    "customer_id": "<CUSTOMER_ID>",
    "employee_id": "<EMPLOYEE_ID>",
    "name": "<NAME>",
    "street_address": "<STREET_ADDRESS>",
    "phone_number": "<PHONE_NUMBER>",
    "ipv4": "<IPV4>",
    "credit_card_number": "<CREDIT_CARD_NUMBER>",
    "license_plate": "<LICENSE_PLATE>",
    "address": "<ADDRESS>",
    "user_name": "<USERNAME>",
    "device_identifier": "<DEVICE_IDENTIFIER>",
    "bank_routing_number": "<BANK_ROUTING_NUMBER>",
    "date_time": "<DATE_TIME>",
    "company_name": "<COMPANY_NAME>",
    "unique_identifier": "<UNIQUE_IDENTIFIER>",
    "biometric_identifier": "<BIOMETRIC_IDENTIFIER>",
    "account_number": "<ACCOUNT_NUMBER>",
    "city": "<CITY>",
    "certificate_license_number": "<CERTIFICATE_LICENSE_NUMBER>",
    "time": "<TIME>",
    "postcode": "<POSTCODE>",
    "vehicle_identifier": "<VEHICLE_IDENTIFIER>",
    "coordinate": "<COORDINATE>",
    "country": "<COUNTRY>",
    "api_key": "<API_KEY>",
    "ipv6": "<IPV6>",
    "password": "<PASSWORD>",
    "health_plan_beneficiary_number": "<HEALTH_PLAN_BENEFICIARY_NUMBER>",
    "national_id": "<NATIONAL_ID>",
    "tax_id": "<TAX_ID>",
    "url": "<URL>",
    "state": "<STATE>",
    "swift_bic": "<SWIFT_BIC>",
    "cvv": "<CVV>",
    "pin": "<PIN>"
}

print("[PII] Loading GLiNER PII model...")
model = GLiNER.from_pretrained(MODEL_PATH)
print("[PII] PII model ready!")

# =========================
# PUBLIC API
# =========================
def detect_pii(text: str, threshold: float = 0.25):
    """
    Detect PII entities in text using ML model and return list of dicts
    """
    raw_entities = model.predict_entities(
        text,
        labels=PII_LABELS,
        threshold=threshold
    )

    processed_entities = []
    for ent in raw_entities:
        label = ent.get("type") or ent.get("label") or ent.get("entity") or "PII"
        placeholder = LABEL_PLACEHOLDERS.get(label, f"<{label.upper()}>")
        ent_text = ent.get("text") or ent.get("value")
        if ent_text:
            processed_entities.append({
                "start": ent.get("start"),
                "end": ent.get("end"),
                "text": ent_text,
                "label": label,
                "placeholder": placeholder
            })

    return processed_entities


def mask_pii(text: str, entities: list):
    """
    Replace all detected PII entities wit`h placeholders
    """
    masked_text = text
    for ent in sorted(entities, key=lambda x: x["start"], reverse=True):
        masked_text = masked_text[:ent["start"]] + ent["placeholder"] + masked_text[ent["end"]:]
    return masked_text

