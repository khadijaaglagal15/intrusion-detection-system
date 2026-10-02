import os
import sqlite3
import joblib
import pandas as pd

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    jsonify
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename




app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-in-production"
)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"csv"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)



@app.route('/')
def index():
    return render_template('index.html')

@app.route("/about")
def about():
    return render_template("about.html")


@app.route('/home')
def home():
	return render_template('home.html')


@app.route('/logon')
def logon():
	return render_template('signup.html')

@app.route('/login')
def login():
	return render_template('signin.html')


@app.route('/home1')
def home1():
	return render_template('home1.html')


@app.route('/signup', methods=['POST'])
def signup():

    username = request.form.get('user', '')
    name = request.form.get('name', '')
    email = request.form.get('email', '')
    mobile = request.form.get('mobile', '')
    password = request.form.get('password', '')

    conn = sqlite3.connect("signup.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS info(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            name TEXT,
            email TEXT,
            mobile TEXT,
            password TEXT
        )
    """)

    cursor.execute("""
        INSERT INTO info(user,name,email,mobile,password)
        VALUES(?,?,?,?,?)
    """, (username, name, email, mobile, password))

    conn.commit()
    conn.close()

    return render_template("signin.html")

@app.route('/predict_lo', methods=['POST'])
def predict_lo():
    global otp, username, name, email, number, password
    if request.method == 'POST':
        message = request.form['message']
        print(message)
        if int(message) == otp:
            print("TRUE")
            con = sqlite3.connect('signup.db')
            cur = con.cursor()
            cur.execute("insert into `info` (`user`,`email`, `password`,`mobile`,`name`) VALUES (?, ?, ?, ?, ?)",(username,email,password,number,name))
            con.commit()
            con.close()
            return render_template("signin.html")
    return render_template("signup.html")

@app.route("/signin")
def signin():

    mail1 = request.args.get('user','')
    password1 = request.args.get('password','')
    con = sqlite3.connect('signup.db')
    cur = con.cursor()
    cur.execute("select `user`, `password` from info where `user` = ? AND `password` = ?",(mail1,password1,))
    data = cur.fetchone()

    if data == None:
        return render_template("signin.html")    

    elif mail1 == str(data[0]) and password1 == str(data[1]):
        return render_template("home.html")
    else:
        return render_template("signin.html")

@app.route("/notebook1")
def notebook1():
    return render_template("CIC-IDS-2017.html")

@app.route("/notebook2")
def notebook2():
    return render_template("CIC-IDS-2018.html")


@app.route('/predict', methods=['POST'])
def predict():

    model = joblib.load("model/intrusion_model.pkl")

    features = []

    for i in range(23):
        features.append(float(request.form[str(i)]))

    prediction = model.predict([features])[0]

    if prediction == 1:
        output = "There is an Attack Detected!"
    else:
        output = "There is No Attack Detected, it is Normal!"

    return render_template("prediction.html", output=output)


@app.route('/predict1', methods=['POST'])
def predict1():

    model = joblib.load("model/intrusion_model.pkl")

    features = []

    for i in range(23):
        features.append(float(request.form[str(i)]))

    prediction = model.predict([features])[0]

    if prediction == 1:
        output = "There is an Attack Detected!"
    else:
        output = "There is No Attack Detected, it is Normal!"

    return render_template("prediction1.html", output=output)

@app.route("/upload")
def upload():
    return render_template("upload.html")


@app.route("/predict_csv", methods=["POST"])
def predict_csv():

    # 1. Vérifier si un fichier a été envoyé
    if "file" not in request.files:
        return "No file uploaded"

    file = request.files["file"]

    # 2. Vérifier si un fichier a été sélectionné
    if file.filename == "":
        return "No file selected"

    # 3. Vérifier que le fichier est CSV
    if not file.filename.lower().endswith(".csv"):
        return "Please upload a CSV file"

    # 4. Lire le fichier CSV
    df = pd.read_csv(file)
    df.columns = df.columns.str.strip()
    
    # 6. Charger le modèle
    model = joblib.load("model/intrusion_model.pkl")

    # 7. Les 23 features utilisées par le modèle
    features = [
        "Flow Duration",
        "Total Length of Fwd Packets",
        "Fwd Packet Length Max",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Std",
        "Flow IAT Max",
        "Fwd IAT Max",
        "Fwd Header Length",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Max Packet Length",
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",
        "Average Packet Size",
        "Avg Fwd Segment Size",
        "Fwd Header Length.1",
        "Subflow Fwd Bytes",
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward"
    ]

    # 8. Vérifier que les 23 features existent
    missing_features = [
        feature for feature in features
        if feature not in df.columns
    ]

    if missing_features:
        return f"Missing columns: {missing_features}"

    # 9. Garder uniquement les 23 features
    X = df[features]

    # 10. Faire la prédiction
    predictions = model.predict(X)

    # 11. Ajouter les prédictions
    df["Prediction"] = predictions

    # 12. Transformer 0/1 en texte
    df["Result"] = df["Prediction"].apply(
        lambda x: "Normal" if x == 0 else "Attack"
    )

    # 13. Compter les résultats
    normal_count = (df["Prediction"] == 0).sum()
    attack_count = (df["Prediction"] == 1).sum()

    # 14. Retourner les résultats
    return {
        "total_flows": len(df),
        "normal": int(normal_count),
        "attacks": int(attack_count),
        "predictions": df[
            ["Prediction", "Result"]
        ].to_dict(orient="records")
    }
    
if __name__ == "__main__":
    app.run(debug=True)