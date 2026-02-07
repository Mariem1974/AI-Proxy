from flask import Flask, render_template, request, Response, jsonify
from LLM import chat_stream, reset_memory

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("chat.html")


@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message", "")

    def generate():
        for token in chat_stream(user_input):
            yield token

    return Response(generate(), mimetype="text/plain")


@app.route("/reset", methods=["POST"])
def reset():
    reset_memory()
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
