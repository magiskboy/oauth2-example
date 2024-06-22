from flask import Flask, redirect, url_for, request, abort, jsonify
import requests
import jwt


app = Flask(__name__)

client_id = "ANk48VjEGe_Wiq9ARTl_lo0bBbiXOxkPk4TFDVgh4Cw"
client_secret = "C2FFZnHx8zbAAszGEZfrh8XyHmZVQnijlM8GWfK622s"
jwks = requests.get("http://127.0.0.1:5000/.well-known/jwks.json").json()
key = None
print(jwks)
for k in jwks["keys"]:
    if k["kid"] == client_id:
        key = jwt.algorithms.RSAAlgorithm.from_jwk(k)
        break


@app.route("/")
def index():
    return redirect(
        f'http://127.0.0.1:5000/authorize?grant_type=code&client_id={client_id}&client_secret={client_secret}&redirect_uri={url_for("callback", _external=True)}&scopes=openid'
    )


@app.route("/callback")
def callback():
    code = request.args.get("code")
    redirect_uri = url_for("callback")
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "code": code,
    }
    res = requests.post("http://127.0.0.1:5000/token", json=data)

    if res.status_code == 200:
        data = res.json()
        access_token = data["access_token"]
        claims = jwt.decode(access_token, key, algorithms=["RS256"])
        return jsonify(claims)


    abort(400, description=res.json())

if __name__ == "__main__":
    app.run(port=3000, debug=True)