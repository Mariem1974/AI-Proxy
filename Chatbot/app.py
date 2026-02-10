# 1st code without gliner work

# from flask import Flask, render_template, request, Response, jsonify
# from LLM import chat_stream, reset_memory
# from Classifier import predict_probability
# from spacy_rule_engine import SpacyRuleEngine
# import state 
# from Rephrase_Engine import InputRewriter
# from PII import detect_pii

# app = Flask(__name__)

# #------------------- * ----------------------#
# spacy_engine = SpacyRuleEngine()
# input_rewriter = InputRewriter()
# #------------------- * ----------------------#

# @app.route("/")
# def index():
#     return render_template(
#         "chat.html",
#         spacy=state.FEATURES["SPACY_FIREWALL"],
#         bert=state.FEATURES["BERT_FIREWALL"],
#         pii=state.FEATURES["PII_FIREWALL"]
#     )

# # ------------------- admin ----------------------#
# @app.route("/admin")
# def admin():
#     return render_template("admin.html", features=state.FEATURES)

# @app.route("/toggle/spacy", methods=["POST"])
# def toggle_spacy():
#     state.FEATURES["SPACY_FIREWALL"] = not state.FEATURES["SPACY_FIREWALL"]
#     return jsonify(state.FEATURES)

# @app.route("/toggle/bert", methods=["POST"])
# def toggle_bert():
#     state.FEATURES["BERT_FIREWALL"] = not state.FEATURES["BERT_FIREWALL"]
#     return jsonify({"bert": state.FEATURES["BERT_FIREWALL"]})

# @app.route("/toggle/pii", methods=["POST"])
# def toggle_pii():
#     state.FEATURES["PII_FIREWALL"] = not state.FEATURES["PII_FIREWALL"]
#     return jsonify({"pii": state.FEATURES["PII_FIREWALL"]})
# # ------------------- admin ----------------------#

# # @app.route("/chat", methods=["POST"])
# # def chat():
# #     user_input = request.json.get("message", "")

# #     def generate():
# #         for token in chat_stream(user_input):
# #             yield token
# #     return Response(generate(), mimetype="text/plain")

# # @app.route("/chat", methods=["POST"])
# # def chat():
# #     data = request.get_json()
# #     user_input = data.get("message", "")

# #     # ============================
# #     # PHASE 1 — spaCy INPUT FIREWALL
# #     # ============================
# #     if state.FEATURES["SPACY_FIREWALL"]:
# #         analysis = spacy_engine.analyze_prompt(user_input)

# #         if analysis["malicious"]:
# #             def blocked():
# #                 yield "❌ Prompt blocked by spaCy Security Firewall.\n\n"
# #                 for hit in analysis["matcher_hits"]:
# #                     yield f"• {hit['type']} → `{hit['text']}`\n"
# #                 for hit in analysis["regex_hits"]:
# #                     yield f"• {hit['type']} → `{hit['text']}`\n"

# #             return Response(blocked(), mimetype="text/plain")

# #     # ============================
# #     # SAFE → SEND TO LLM
# #     # ============================
# #     return Response(
# #         chat_stream(user_input),
# #         mimetype="text/plain"
# #     )

# @app.route("/chat", methods=["POST"])
# def chat():
#     user_input = request.json.get("message", "")
#     # =========================
#     # PHASE 1: INPUT FIREWALL
#     # =========================
#     # 1️⃣ SPACY FILTER
#     if state.FEATURES["SPACY_FIREWALL"]:
#         spacy_result = spacy_engine.analyze_prompt(user_input)
#         if spacy_result["malicious"]:
#             return jsonify({"message": "⚠️ Your message seems malicious (detected by spaCy)."}), 400

#     # 2️⃣ BERT FILTER
#     if state.FEATURES["BERT_FIREWALL"]:
#         prob = predict_probability(user_input)  # returns 0-1 probability
#         if prob < 0.4:  # SAFE
#             safe_input = user_input
#         elif 0.4 <= prob < 0.7:  # MEDIUM → rewrite
#             safe_input = input_rewriter.rewrite(user_input)
#         else:  # HIGH → block
#             return jsonify({"message": "⚠️ Your message seems malicious (detected by BERT)."}), 400
#     else:
#         safe_input = user_input

#      # =========================
#     # SEND TO LLM
#     # =========================
#     response_text = "".join(chat_stream(safe_input))

#     # =========================
#     # PHASE 2: OUTPUT PII FILTER
#     # =========================
#     if state.FEATURES["PII_FIREWALL"]:
#         entities = detect_pii(response_text)
#         print("PII entities:", entities)
#         # for ent in entities:
#         #     placeholder = f"<{ent['type']}>"
#         #     response_text = response_text.replace(ent['text'], placeholder)
#         for ent in entities:
#             ent_type = (
#                 ent.get("type") or
#                 ent.get("label") or
#                 ent.get("entity") or
#                 "PII"
#             )

#             ent_text = (
#                 ent.get("text") or
#                 ent.get("value")
#             )

#             if ent_text:
#                 placeholder = f"<{ent_type}>"
#                 response_text = response_text.replace(ent_text, placeholder)

#     return Response(response_text, mimetype="text/plain")


# # @app.route("/chat", methods=["POST"])
# # def chat():
# #     user_input = request.json.get("message", "")
    
# #     # =========================
# #     # PHASE 1: INPUT FIREWALL
# #     # =========================
# #     # 1️⃣ SPACY FILTER
# #     if state.FEATURES["SPACY_FIREWALL"]:
# #         spacy_result = spacy_engine.analyze_prompt(user_input)
# #         if spacy_result["malicious"]:
# #             return jsonify({"message": "⚠️ Your message seems malicious (detected by spaCy)."}), 400

# #     # 2️⃣ BERT FILTER WITH REPHRASE LOOP
# #     safe_input = user_input
# #     if state.FEATURES["BERT_FIREWALL"]:
# #         max_rewrites = 3
# #         iteration = 0

# #         while iteration < max_rewrites:
# #             prob = predict_probability(safe_input)  # 0-1 probability for Malicious
# #             if prob < 0.4:  # SAFE
# #                 break
# #             elif 0.4 <= prob < 0.7:  # MEDIUM → rewrite
# #                 iteration += 1
# #                 safe_input = input_rewriter.rewrite(safe_input)
# #             else:  # HIGH → block
# #                 return jsonify({"message": "⚠️ Your message seems malicious (detected by BERT)."}), 400
# #         else:
# #             # Exceeded max rephrases → treat as HIGH
# #             return jsonify({"message": "⚠️ Your message seems malicious after multiple rewrites."}), 400

# #     # =========================
# #     # SEND TO LLM
# #     # =========================
# #     def generate():
# #         for token in chat_stream(safe_input):
# #             yield token

# #     return Response(generate(), mimetype="text/plain")


# @app.route("/reset", methods=["POST"])
# def reset():
#     reset_memory()
#     return jsonify({"status": "ok"})


# if __name__ == "__main__":
#     app.run(debug=True)


# 2nd code with gliner work but missing entities

from flask import Flask, render_template, request, Response, jsonify
from LLM import chat_stream, reset_memory
from Classifier import predict_probability
from spacy_rule_engine import SpacyRuleEngine
import state 
from Rephrase_Engine import InputRewriter, OutputRewriter
from PII import detect_pii, mask_pii, LABEL_PLACEHOLDERS

app = Flask(__name__)

#------------------- * ----------------------#
spacy_engine = SpacyRuleEngine()
input_rewriter = InputRewriter()
output_rewriter = OutputRewriter()
#------------------- * ----------------------#

@app.route("/")
def index():
    return render_template(
        "chat.html",
        spacy=state.FEATURES["SPACY_FIREWALL"],
        bert=state.FEATURES["BERT_FIREWALL"],
        pii=state.FEATURES["PII_FIREWALL"]
    )

# ------------------- admin ----------------------#
@app.route("/admin")
def admin():
    return render_template("admin.html", features=state.FEATURES)

@app.route("/toggle/spacy", methods=["POST"])
def toggle_spacy():
    state.FEATURES["SPACY_FIREWALL"] = not state.FEATURES["SPACY_FIREWALL"]
    return jsonify(state.FEATURES)

@app.route("/toggle/bert", methods=["POST"])
def toggle_bert():
    state.FEATURES["BERT_FIREWALL"] = not state.FEATURES["BERT_FIREWALL"]
    return jsonify({"bert": state.FEATURES["BERT_FIREWALL"]})

@app.route("/toggle/pii", methods=["POST"])
def toggle_pii():
    state.FEATURES["PII_FIREWALL"] = not state.FEATURES["PII_FIREWALL"]
    return jsonify({"pii": state.FEATURES["PII_FIREWALL"]})
# ------------------- admin ----------------------#

@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message", "")

    # =========================
    # PHASE 1: INPUT FIREWALL
    # =========================
    # 1️⃣ SPACY FILTER
    if state.FEATURES["SPACY_FIREWALL"]:
        spacy_result = spacy_engine.analyze_prompt(user_input)
        if spacy_result["malicious"]:
            return jsonify({"message": "⚠️ Your message seems malicious (detected by spaCy)."}), 400

    # 2️⃣ BERT FILTER
    if state.FEATURES["BERT_FIREWALL"]:
        prob = predict_probability(user_input)  # returns 0-1 probability
        if prob < 0.4:  # SAFE
            safe_input = user_input
        elif 0.4 <= prob < 0.7:  # MEDIUM → rewrite
            safe_input = input_rewriter.rewrite(user_input)
        else:  # HIGH → block
            return jsonify({"message": "⚠️ Your message seems malicious (detected by BERT)."}), 400
    else:
        safe_input = user_input

    # =========================
    # SEND TO LLM
    # =========================
    response_text = "".join(chat_stream(safe_input))

    # =========================
    # PHASE 2: OUTPUT PII FILTER
    # =========================
    if state.FEATURES["PII_FIREWALL"]:
        entities = detect_pii(response_text)
        response_text = mask_pii(response_text, entities)
        # print("PII entities:", entities)  # debug


    # If GLiNER detected any PII, further redact using OutputRewriter
        if entities:
            response_text = output_rewriter.redact(response_text)

        # for ent in entities:
        #     # Get raw label and text safely
        #     raw_label = ent.get("type") or ent.get("label") or ent.get("entity") or "PII"
        #     ent_text = ent.get("text") or ent.get("value")
        #     if not ent_text:
        #         continue

        #     # Map raw label to friendly placeholder
        #     placeholder_label = LABEL_PLACEHOLDERS.get(raw_label.lower(), "PII")
        #     placeholder = f"<{placeholder_label}>"

        #     # Replace all occurrences in response
        #     response_text = response_text.replace(ent_text, placeholder)

    return Response(response_text, mimetype="text/plain")

@app.route("/reset", methods=["POST"])
def reset():
    reset_memory()
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True)



# from flask import Flask, render_template, request, Response, jsonify
# from LLM import chat_stream, reset_memory
# from Classifier import predict_probability
# from spacy_rule_engine import SpacyRuleEngine
# import state
# from Rephrase_Engine import InputRewriter ,  OutputRewriter
# from gliner import GLiNER
# from PII import detect_pii


# app = Flask(__name__)

# # ------------------- * ----------------------#
# spacy_engine = SpacyRuleEngine()
# input_rewriter = InputRewriter()
# output_rewriter = OutputRewriter()

# # Load GLiNER for PII detection
# MODEL_PATH = r"C:\Users\ahmed\OneDrive\Desktop\Clean_Project\AI-Proxy\Chatbot\models\gretel-gliner\models--gretelai--gretel-gliner-bi-large-v1.0\snapshots\f96d1da43b97bd1846b14a7068a57e1ab15f226e"
# pii_model = GLiNER.from_pretrained(MODEL_PATH)
# # ------------------- * ----------------------#

# @app.route("/")
# def index():
#     return render_template(
#         "chat.html",
#         spacy=state.FEATURES["SPACY_FIREWALL"],
#         bert=state.FEATURES["BERT_FIREWALL"],
#         pii=state.FEATURES["PII_FIREWALL"]
#     )

# # ------------------- admin ----------------------#
# @app.route("/admin")
# def admin():
#     return render_template("admin.html", features=state.FEATURES)

# @app.route("/toggle/spacy", methods=["POST"])
# def toggle_spacy():
#     state.FEATURES["SPACY_FIREWALL"] = not state.FEATURES["SPACY_FIREWALL"]
#     return jsonify(state.FEATURES)

# @app.route("/toggle/bert", methods=["POST"])
# def toggle_bert():
#     state.FEATURES["BERT_FIREWALL"] = not state.FEATURES["BERT_FIREWALL"]
#     return jsonify({"bert": state.FEATURES["BERT_FIREWALL"]})

# @app.route("/toggle/pii", methods=["POST"])
# def toggle_pii():
#     state.FEATURES["PII_FIREWALL"] = not state.FEATURES["PII_FIREWALL"]
#     return jsonify({"pii": state.FEATURES["PII_FIREWALL"]})
# # ------------------- admin ----------------------#

# @app.route("/chat", methods=["POST"])
# def chat():
#     user_input = request.json.get("message", "")

#     # =========================
#     # PHASE 1: INPUT FIREWALL
#     # =========================
#     if state.FEATURES["SPACY_FIREWALL"]:
#         spacy_result = spacy_engine.analyze_prompt(user_input)
#         if spacy_result["malicious"]:
#             return jsonify({"message": "⚠️ Your message seems malicious (detected by spaCy)."}), 400

#     # BERT FILTER WITH REPHRASE LOOP
#     safe_input = user_input
#     if state.FEATURES["BERT_FIREWALL"]:
#         max_rewrites = 3
#         iteration = 0

#         while iteration < max_rewrites:
#             prob = predict_probability(safe_input)
#             if prob < 0.4:  # SAFE
#                 break
#             elif 0.4 <= prob < 0.7:  # MEDIUM → rewrite
#                 iteration += 1
#                 safe_input = input_rewriter.rewrite(safe_input)
#             else:  # HIGH → block
#                 return jsonify({"message": "⚠️ Your message seems malicious (detected by BERT)."}), 400
#         else:
#             return jsonify({"message": "⚠️ Your message seems malicious after multiple rewrites."}), 400

#     # =========================
#     # SEND TO LLM
#     # =========================
#     response_text = "".join(chat_stream(safe_input))

#     # =========================
#     # PHASE 2: OUTPUT PII FILTER
#     # =========================
#     if state.FEATURES["PII_FIREWALL"]:
#         entities = detect_pii(response_text)

#         if entities:
#             # Log detected types (optional)
#             detected_types = ", ".join(set(e["label"] for e in entities))
#             print(f"[PII DETECTED] {detected_types}")

#             # Rewrite & redact response instead of blocking
#             safe_response = output_rewriter.redact(response_text)

#             return jsonify({
#                 "message": safe_response,
#                 "notice": "⚠️ Sensitive information was automatically redacted."
#             })
        
#     return jsonify({"message": response_text})

# @app.route("/reset", methods=["POST"])
# def reset():
#     reset_memory()
#     return jsonify({"status": "ok"})

# if __name__ == "__main__":
#     app.run(debug=True)


# from flask import Flask, render_template, request, jsonify
# from LLM import chat_stream, reset_memory
# from Classifier import predict_probability
# from spacy_rule_engine import SpacyRuleEngine
# import state
# from Rephrase_Engine import InputRewriter, OutputRewriter
# from PII import detect_pii

# app = Flask(__name__)

# # =========================
# # INIT ENGINES
# # =========================
# spacy_engine = SpacyRuleEngine()
# input_rewriter = InputRewriter()
# output_rewriter = OutputRewriter()

# # =========================
# # ROUTES
# # =========================
# @app.route("/")
# def index():
#     return render_template(
#         "chat.html",
#         spacy=state.FEATURES["SPACY_FIREWALL"],
#         bert=state.FEATURES["BERT_FIREWALL"],
#         pii=state.FEATURES["PII_FIREWALL"]
#     )

# # =========================
# # ADMIN
# # =========================
# @app.route("/admin")
# def admin():
#     return render_template("admin.html", features=state.FEATURES)

# @app.route("/toggle/spacy", methods=["POST"])
# def toggle_spacy():
#     state.FEATURES["SPACY_FIREWALL"] = not state.FEATURES["SPACY_FIREWALL"]
#     return jsonify(state.FEATURES)

# @app.route("/toggle/bert", methods=["POST"])
# def toggle_bert():
#     state.FEATURES["BERT_FIREWALL"] = not state.FEATURES["BERT_FIREWALL"]
#     return jsonify({"bert": state.FEATURES["BERT_FIREWALL"]})

# @app.route("/toggle/pii", methods=["POST"])
# def toggle_pii():
#     state.FEATURES["PII_FIREWALL"] = not state.FEATURES["PII_FIREWALL"]
#     return jsonify({"pii": state.FEATURES["PII_FIREWALL"]})

# # =========================
# # CHAT
# # =========================
# @app.route("/chat", methods=["POST"])
# def chat():
#     user_input = request.json.get("message", "")

#     # =========================
#     # PHASE 1 — INPUT FIREWALL
#     # =========================
#     if state.FEATURES["SPACY_FIREWALL"]:
#         spacy_result = spacy_engine.analyze_prompt(user_input)
#         if spacy_result["malicious"]:
#             return jsonify({
#                 "message": "⚠️ Your message seems malicious (detected by spaCy)."
#             }), 400

#     safe_input = user_input

#     if state.FEATURES["BERT_FIREWALL"]:
#         max_rewrites = 3
#         iteration = 0

#         while iteration < max_rewrites:
#             prob = predict_probability(safe_input)

#             if prob < 0.4:
#                 break  # SAFE

#             elif 0.4 <= prob < 0.7:
#                 iteration += 1
#                 safe_input = input_rewriter.rewrite(safe_input)

#             else:
#                 return jsonify({
#                     "message": "⚠️ Your message seems malicious (detected by BERT)."
#                 }), 400

#         if iteration == max_rewrites:
#             return jsonify({
#                 "message": "⚠️ Prompt blocked after multiple unsafe rewrites."
#             }), 400

#     # =========================
#     # LLM CALL (NON-STREAM)
#     # =========================
#     response_text = "".join(chat_stream(safe_input))

#     # =========================
#     # PHASE 2 — OUTPUT PII FIREWALL
#     # =========================
#     if state.FEATURES["PII_FIREWALL"]:
#         entities = detect_pii(response_text)

#         if entities:
#             detected_types = ", ".join(
#                 sorted(set(e["label"] for e in entities))
#             )

#             print(f"[PII DETECTED] {detected_types}")

#             redacted = output_rewriter.redact(response_text)

#             return jsonify({
#                 "message": redacted,
#                 "notice": "⚠️ Sensitive information was automatically redacted."
#             })

#     # =========================
#     # FINAL SAFE RESPONSE
#     # =========================
#     return jsonify({"message": response_text})

# # =========================
# # RESET
# # =========================
# @app.route("/reset", methods=["POST"])
# def reset():
#     reset_memory()
#     return jsonify({"status": "ok"})

# # =========================
# # MAIN
# # =========================
# if __name__ == "__main__":
#     app.run(debug=True)
