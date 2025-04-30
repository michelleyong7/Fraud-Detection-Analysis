# Fraud Detection Project: Multi-Rule Behavioral Scoring System


# This notebook demonstrates how to detect suspicious transaction patterns using Python and pandas, specifically targeting users who make more than 5 transactions in a single hour - a common fraud indicator.

#step 1: load data

import pandas as pd
import matplotlib.pyplot as plt


df = pd.read_csv("./data/fraud_detection_transactions.csv")
df.head()

##step 2: inspect data

df.info()

##step 3: extract time features

df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour
df['txn_hour'] = df['timestamp'].dt.floor('H')


##step 4: analyze hourly volume

df['hour'].value_counts().sort_index()

##step 5: detect high-frequency transactions

txn_counts = df.groupby(['user_id', 'txn_hour']).size().reset_index(name='txn_count')
high_freq_users = txn_counts[txn_counts['txn_count'] > 5]


##step 6: tag suspicious transactions


df = df.merge(high_freq_users[['user_id', 'txn_hour']], on=['user_id', 'txn_hour'], how='left', indicator=True)
df['high_freq_flag'] = (df['_merge'] == 'both').astype(int)
df.drop('_merge', axis=1, inplace=True)

## step 7: export flagged users


df[df['high_freq_flag'] == 1].to_csv("./data/high_frequency_users.csv", index=False)

## done with rule 1

##fraud rule 2: transactions between 2AM-4AM

##flagging transactions that occur during unusual hours- specifically 2:00 AM and 4:59 AM. This window is commonly associated with automated fraud behavior.

##step 1: load & prepare data
import sqlite3

df = pd.read_csv("./data/fraud_detection_transactions.csv")
df['timestamp'] = pd.to_datetime(df['timestamp'])

##step 2: save to sqlite
conn = sqlite3.connect("../sql/fraud_detection.db")
df.to_sql('transactions', conn, if_exists='replace', index=False)

##step 3: query unusual time transactions
query = """
SELECT *
FROM transactions
WHERE CAST(strftime('%H', timestamp) AS INTEGER) BETWEEN 2 AND 4
"""

unusual_time_df = pd.read_sql_query(query, conn)
unusual_time_df.head()

##step 4: export results
unusual_time_df.to_csv("./data/unusual_time_transactions.csv", index=False)

#step 5: visualize suspicious activity
unusual_time_df['hour'] = pd.to_datetime(unusual_time_df['timestamp']).dt.hour
unusual_time_df['hour'].value_counts().sort_index().plot(
    kind='bar',
    color='darkred',
    figsize=(8, 4)
)
plt.title("Suspicious Transactions by Hour (2AM–4AM)")
plt.xlabel("Hour of Day")
plt.ylabel("Transaction Count")
plt.xticks(rotation=0)
plt.grid(axis='y')
plt.tight_layout()
plt.show()

##findings:

##found 3834 transactions occurring between 2AM and 4AM, made by 3119 unique users. 
##these transactions may warrant further review, especially if they involve high amounts or repetitive behavior. 

##fraud rule 3

#objective: identify users who issue more than 3 refunds in a single calendar month, which may indicate return abuse or refund policy exploitation

#step 1: add 'month' column for monthly grouping
df['month'] = pd.to_datetime(df['timestamp']).dt.to_period('M')

#step 2: count refunds per user per month
refunds_by_user_month = (
    df[df['refund_flag'] == 1]
    .groupby(['user_id', 'month'])
    .size()
    .reset_index(name='refund_count')
)

#step 3: filter for users with >3 refunds
refund_heavy_users = refunds_by_user_month[refunds_by_user_month['refund_count'] > 3]

#step 4: tag refund-heavy transactions
df = df.merge(
    refund_heavy_users[['user_id', 'month']],
    on=['user_id', 'month'],
    how='left',
    indicator=True
)
df['refund_heavy_flag'] = (df['_merge'] == 'both').astype(int)
df.drop(columns=['_merge'], inplace=True)

#step 5: export flagged transactions 
df[df['refund_heavy_flag'] == 1].to_csv("data/refund_heavy_users.csv", index=False)

#summary: this rule ran successfully, but there were no users found with >3 refunds per month.

##fraud rule 4
#objective: identify device ID's used by 5 or more unique users which could indicate shared or compromised devices

#step 1: count unique users per device
shared_devices = df.groupby('device_id')['user_id'].nunique().reset_index(name='user_count')

#step 2: filter devices with 5 or more users
abused_devices = shared_devices[shared_devices['user_count'] >= 5]

#step 3: tag matching transactions in main dataset
df = df.merge(abused_devices[['device_id']], on='device_id', how='left', indicator=True)
df['shared_device_flag'] = (df['_merge'] == 'both').astype(int)
df.drop(columns=['_merge'], inplace=True)

#step 4: export flagged transactions
df[df['shared_device_flag'] == 1].to_csv('data/shared_device_users.csv', index=False)

#summary: this rule identifies accounts likely sharing access with the same device.
#patterns are worth a deeper review even though this dataset has 0 flagged transactions

# fraud rule #5: transaction amount spikes
# objective: detect users who suddenly make a transaction that is 3x or more above their average.

# step 1: compute user average amount
user_avg = df.groupby('user_id')['amount'].mean().reset_index(name='avg_amount')

# step 2: merge into main dataset
df = df.merge(user_avg, on='user_id')

# step 3: flag spike transactions
df['amount_spike_flag'] = (df['amount'] > 3 * df['avg_amount']).astype(int)

# step 4: export spike transactions
df[df['amount_spike_flag'] == 1].to_csv('data/amount_spike_users.csv', index=False)

# summary:
#this rule helps uncover unusually large purchases that deviate from normal user behavior.
#we discovered 24 high spike transactions in this dataset

# fraud rule 6: assign risk scores
# objective: calculate a composite fraud risk score based on key behavioral indicators

# step 1: build weighted score
df['risk_score'] = (
    (df['hour'].isin([2, 3, 4]) * 2) +               # unusual transaction hours
    (df['refund_flag'] * 3) +                        # refund activity
    (df['amount'] > 1000).astype(int) * 2 +          # large transactions
    (df['shared_device_flag'] * 2) +                 # shared device use
    (df['high_freq_flag'] * 3) +                     # high frequency activity
    (df['amount_spike_flag'] * 2)                    # sudden spikes
)

# step 2: filter high-risk transactions (score >= 5)
high_risk = df[df['risk_score'] >= 5]

# step 3: export high-risk users
high_risk.to_csv('data/high_risk_users.csv', index=False)

# summary: risk scoring helps consolidate multiple red flags into a single prioritization metric.
# this rule allows faster identification of users exhibiting multiple forms of suspicious behavior.

# fraud rule 7: high-risk user flagging
# objective: output users with highest risk for further investigation

# step 1: select transactions with score ≥ 5
high_risk = df[df['risk_score'] >= 5]

# step 2: export to file (ensure 'data' folder exists)
high_risk.to_csv("./data/high_risk_users.csv", index=False)

# summary
print(f"flagged {high_risk['user_id'].nunique()} high-risk users with risk scores ≥ 5.")

