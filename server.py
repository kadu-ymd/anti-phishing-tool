from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import re
import requests
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins, for development. Specify your actual origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SPECIAL_CHAR = "[@_!#$%^&*()<>?/\|}{~:]"
NUM_CHAR = "[0-9]"
URL_POST_FIND = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="


class URLRequest(BaseModel):
    url: str

def find_pattern(string, pattern):
    regex = re.compile(pattern)
    return bool(regex.search(string))

def check_phishing(url):
    url_post = f"{URL_POST_FIND}{API_KEY}"

    body_post = {
        "client": {
            "clientId": "anti-phishing-tool",
            "clientVersion": "0.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(url_post, json=body_post)
        if response.status_code == 200 and response.json():
            return "Phishing ou malicioso detectado!"
        else:
            return "URL segura."
    except Exception as e:
        return f"Erro ao verificar: {e}"

@app.get("/")
def read_root():
    with open("index.html") as f:
        return f.read()

@app.post("/check")
async def check_url(request: URLRequest):
    url = request.url
    suspicious_chars = []

    if find_pattern(url, SPECIAL_CHAR):
        suspicious_chars.append("caracteres especiais")
    if find_pattern(url, NUM_CHAR):
        suspicious_chars.append("números incomuns")

    if suspicious_chars:
        format_check = f"Aviso: A URL contém {', '.join(suspicious_chars)}, o que pode indicar phishing."
    else:
        format_check = "A URL parece normal em termos de formatação."

    api_check = check_phishing(url)

    return {
        "format_check": format_check,
        "api_check": api_check
    }

# Para rodar: uvicorn server:app --reload