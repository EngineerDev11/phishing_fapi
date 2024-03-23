import uvicorn
from fastapi import FastAPI, Request
import joblib, os


app = FastAPI()

# pkl

phish_model = open('phishing1.pkl', 'rb')
phish_model_ls = joblib.load(phish_model)

# Placeholder database of URL categories (this would ideally come from an external service)
url_categories = {
    "google.com": "Search Engine",
    "bing.com": "Search Engine",

    "facebook.com": "Social Media",
    "instagram.com": "Social Media",

    "flipkart.com": "Shopping",
    "amazon.com": "Shopping",
    "snapdeal.com": "Shopping",


    # Add more URLs and their respective categories as needed
}




# ML Aspect
@app.get('/predict/{feature}')
async def predict(request: Request, features: str):
    url_length = len(features)
    has_https = features.startswith("https://")
    risk_score = 0.5 * url_length + 0.3 if has_https else 0.8

    # Extracting Client IP
    client_ip = request.client.host

    # Extracting Timestamp
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Simulating URL categorization (using the placeholder database)
    url_category = url_categories.get(features, "Uncategorized")


    X_predict = []
    X_predict.append(str(features))
    y_Predict = phish_model_ls.predict(X_predict)
    if y_Predict == 'bad':
        result = "True"
    else:
        result = "False"

    return features, result, risk_score, client_ip, timestamp, url_category


if __name__ == '__main__':
    uvicorn.run(app, host="192.168.1.40", port=8000)
