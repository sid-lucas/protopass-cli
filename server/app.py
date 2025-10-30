from flask import Flask, request, jsonify
from server.user_store import add_user, get_user


app = Flask(__name__)

@app.post("/register")
def register():
    data = request.get_json(force=True)
    username = data.get("username")
    salt = data.get("salt")
    vkey = data.get("vkey")

    # validation
    if not all([username, salt, vkey]):
        return jsonify({"error": "missing fields"}), 400
    if get_user(username):
        return jsonify({"error": "username is already taken"}), 409

    # enregistrement du sel et verifier sous le nouveau username
    add_user(username, salt, vkey)
    print(f"[SERVER] Registered new user '{username}'")
    return jsonify({"status": "ok", "username": username}), 201

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
