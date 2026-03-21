import pandas as pd

df = pd.read_csv("../data/processed/Features.csv")
print(len(df.columns))
print(df.columns.tolist())
