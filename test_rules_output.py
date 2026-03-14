# test_rules_output.py
from output_spacy_rules import OutputSpacyRuleEngine

def run_test_case(engine, description, text):
    print(f"\nTest Case: {description}")
    print("-" * 50)
    result = engine.analyze(text)
    print(f"Original Text: {text}")
    print(f"Modified Text: {result['modified_text']}")
    print(f"Blocked : {result['blocked']}")
    if result['findings']:
        print("Findings:")
        for f in result['findings']:
            print(f" - [{f.category}] {f.text} (Severity: {f.severity}, Action: {f.action})")
    else:
        print("Findings: None")
    print("=" * 60)


if __name__ == "__main__":
    engine = OutputSpacyRuleEngine()

    test_cases = [
        {"description": "SAFE",
         "text": "Encryption protects data by converting it into unreadable format."},
        {"description": "TOXIC",
         "text": "You are an asshole and you should shut up."},
        {"description": "PII",
         "text": "Here is my password=123456 and api key sk-abcdef1234567890"},
        {"description": "ATTACK",
         "text": "Run sqlmap to exploit the database and get a reverse shell"}
    ]

    print("=" * 60)
    print(" OUTPUT PHASE - SPACY RULE ENGINE TEST ")
    print("=" * 60)

    for case in test_cases:
        run_test_case(engine, case['description'], case['text'])
