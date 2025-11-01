# app.py
from flask import Flask, render_template, jsonify, make_response
import pandas as pd
import os
import time

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs", "traffic_log.csv")

def read_csv_safe():
    for _ in range(5):
        try:
            return pd.read_csv(LOG_FILE)
        except Exception:
            time.sleep(0.1)
    # columns include the new domain/url_path fields
    return pd.DataFrame(columns=[
        "timestamp","src_ip","src_port","dst_ip","dst_port",
        "packet_length","proc_name","owner","prediction","domain","url_path"
    ])

@app.after_request
def add_header(resp):
    resp.cache_control.no_store = True  # Disable cache
    return resp

@app.route("/")
def dashboard():
    df = read_csv_safe()
    total = len(df)
    malicious = len(df[df["prediction"]=="Malicious"]) if "prediction" in df.columns else 0
    normal = len(df[df["prediction"]=="Normal"]) if "prediction" in df.columns else 0
    local_count = len(df[df["owner"]=="Local"]) if "owner" in df.columns else 0
    other_count = len(df[df["owner"]=="Other_Device"]) if "owner" in df.columns else 0
    # show last 50 rows (table will render extra columns if present)
    table_html = df.tail(50).to_html(classes='data', index=False)
    return make_response(render_template("dashboard.html",
                                         tables=[table_html],
                                         total=total,
                                         malicious=malicious,
                                         normal=normal,
                                         local_count=local_count,
                                         other_count=other_count))

@app.route("/chart-data")
def chart_data():
    df = read_csv_safe()
    return jsonify({
        "malicious": int(len(df[df["prediction"]=="Malicious"])) if "prediction" in df.columns else 0,
        "normal": int(len(df[df["prediction"]=="Normal"])) if "prediction" in df.columns else 0,
        "local": int(len(df[df["owner"]=="Local"])) if "owner" in df.columns else 0,
        "other": int(len(df[df["owner"]=="Other_Device"])) if "owner" in df.columns else 0
    })

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
