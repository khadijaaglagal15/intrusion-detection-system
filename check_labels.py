import pandas as pd

df = pd.read_csv("dataset/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
df.columns = df.columns.str.strip()

# أول سطر فيه Attack
attack = df[df["Label"] != "BENIGN"].iloc[0]

# طباعة جميع الأعمدة والقيم
for col, value in attack.items():
    print(f"{col}: {value}")