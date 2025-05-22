from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import re
import requests
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Allows all origins, for development. Specify your actual origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# app.mount("/", StaticFiles(directory="./", html=True), name="static")

DOMAIN_PATTERN = r"^(https?:\/\/)?(www\.)?([a-zA-Z\-]+\.)+[a-zA-Z]{2,}(\/[^\s]*)?$"

URL_POST_FIND = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
API_KEY = "AIzaSyDc-ehoHq4pRAdQF05r1m9Cwzw1cBlJspQ"

class URLRequest(BaseModel):
    url: str

def domain_verifier(domain: str) -> bool:
    """Verifica se um domínio possui caracteres estranhos em sua URL

    Args:
        `domain` (str): Domínio a ser verificado (URL).

    Returns:
        `bool`: Se True, passou pela verificação, caso contrário, não passou.
    """
    match = re.search(DOMAIN_PATTERN, domain)

    if match:
        return False

    return True

def check_phishing(url: str, API_KEY: str) -> str:
    """Faz a chamada da API do Google Safe Browsing para verificar se a URL
    está na lista de URLs identificadas como *phishing*.

    Args:
        `url` (str): URL a ser verificada.
        `API_KEY` (str): Chave da API.

    Returns:
        str: Texto indicando se encontrou ou não a URL na lista, ou ainda, o erro ao verificar a URL.
    """

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
            return "URL na lista de sites de phishing"
        else:
            return "URL não encontrada na lista de sites de phishing."
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

    if domain_verifier(url): 
        suspicious_chars.append("caracteres estranhos (números ou caracteres especiais)")

    if suspicious_chars:
        format_check = f"Aviso: A URL contém {', '.join(suspicious_chars)}, o que pode indicar phishing."
    else:
        format_check = "A URL parece normal em termos de formatação."

    api_check = check_phishing(url, API_KEY)

    return {
        "format_check": format_check,
        "api_check": api_check,

    }