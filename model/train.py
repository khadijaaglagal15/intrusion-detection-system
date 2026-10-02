import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# =========================
# 1. Charger le dataset
# =========================

df = pd.read_csv("../dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")


# =========================
# 2. Nettoyage des données
# =========================

# Nettoyer les noms des colonnes
df.columns = df.columns.str.strip()

# Remplacer les valeurs infinies par NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Supprimer les valeurs manquantes
df.dropna(inplace=True)

# Supprimer les doublons
df.drop_duplicates(inplace=True)

print("Shape après nettoyage :", df.shape)


# =========================
# 3. Transformation du Label
# =========================

print("\nDistribution des labels avant transformation :")
print(df["Label"].value_counts())

# BENIGN = 0
# Toutes les attaques = 1
df["Label"] = df["Label"].apply(
    lambda x: 0 if x == "BENIGN" else 1
)

print("\nDistribution des labels après transformation :")
print(df["Label"].value_counts())


# =========================
# 4. Séparer Features / Target
# =========================

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

X = df[features]
y = df["Label"]


print("\nFeatures :", X.shape)
print("Target :", y.shape)


# =========================
# 5. Train / Test Split
# =========================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTrain :", X_train.shape)
print("Test :", X_test.shape)


# =========================
# 6. Création du modèle
# =========================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)


# =========================
# 7. Entraînement
# =========================

print("\nTraining model...")

model.fit(X_train, y_train)

print("Model trained successfully!")


# =========================
# 8. Prédiction
# =========================

y_pred = model.predict(X_test)


# =========================
# 9. Évaluation
# =========================

print("\nAccuracy:")
print(accuracy_score(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# =========================
# 10. Sauvegarde du modèle
# =========================

# Sauvegarder les noms des features
joblib.dump(
    X.columns.tolist(),
    "features.pkl"
)

# Sauvegarder le modèle
joblib.dump(
    model,
    "intrusion_model.pkl"
)

print("\nModel and features saved successfully!")