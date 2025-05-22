from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from fastapi.middleware.cors import CORSMiddleware

from cryptography.hazmat.backends import default_backend

import ssl
import re
import requests
import whois
from datetime import datetime, timezone
import asyncio
import socket
import traceback 

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

DOMAIN_PATTERN = r"^(https?:\/\/)?(www\.)?([a-zA-Z\-]+\.)+[a-zA-Z]{2,}(\/[^\s]*)?$"

URL_POST_FIND = "https://safeBrowse.googleapis.com/v4/threatMatches:find?key="

API_KEY = "AIzaSyDc-ehoHq4pRAdQF05r1m9Cwzw1cBlJspQ"

class URLRequest(BaseModel):
    url: Optional[str] = None

class DomainCheckRequest(BaseModel):
    hostname: str = Field(..., example="google.com", description="O nome do domínio a ser verificado (ex: example.com).")

class CertificateDetailsResponse(BaseModel):
    hostname: str
    issuer: str
    expiration_date: str
    is_expired: bool
    expires_in_days: int | None = None
    domain_matches_certificate: bool
    status_message: str


async def perform_certificate_check(hostname: str, port: int = 443) -> CertificateDetailsResponse:
    context = ssl.create_default_context()
    
    expires_in_days = None

    writer = None
    
    try:
        _, writer = await asyncio.open_connection(
            host=hostname, port=port, ssl=context, server_hostname=hostname
        )
        
        sslsock = writer.get_extra_info('ssl_object')

        if not sslsock:
            raise HTTPException(status_code=500, detail="Não foi possível obter o objeto SSLSocket após a conexão.")

        cert_dict = sslsock.getpeercert(binary_form=False) 
        if not cert_dict:
            raise HTTPException(status_code=500, detail=f"Não foi possível obter o certificado para '{hostname}'.")

        issuer_info = cert_dict.get('issuer', ())
        issuer = "N/A"
        
        issuer_components = []
        for component_tuple in issuer_info:
            for attr_val_pair in component_tuple:
                if isinstance(attr_val_pair, tuple) and len(attr_val_pair) == 2:
                    attr, val = attr_val_pair
                    if attr == 'commonName':
                        issuer_components.insert(0, val)
                    elif attr == 'organizationName':
                        issuer_components.append(val)
                    else:
                        issuer_components.append(f"{attr}={val}")
                elif isinstance(attr_val_pair, str):
                    issuer_components.append(attr_val_pair)
        
        if issuer_components:
            issuer = ", ".join(filter(None, issuer_components))
        else:
            issuer = "Emissor não especificado no certificado"

        not_after_str = cert_dict.get('notAfter')
        if not not_after_str:
            raise HTTPException(status_code=500, detail="Data de expiração não encontrada no certificado.")
        
        try:
            not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            try:
                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y")
                not_after = not_after.replace(tzinfo=timezone.utc)
            except ValueError:
                raise HTTPException(status_code=500, detail="Formato de data de expiração desconhecido no certificado.")
        
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        
        current_time_aware = datetime.datetime.now(timezone.utc)
        is_expired = current_time_aware > not_after

        domain_matches_certificate = False
        ssl_error_message = ""
        try:
            ssl.match_hostname(cert_dict, hostname)
            domain_matches_certificate = True
        except ssl.CertificateError as e:
            domain_matches_certificate = False
            ssl_error_message = str(e)
        except Exception as e:
            print(f"DEBUG: Erro inesperado ao verificar match de domínio para {hostname}: {e}")
            traceback.print_exc()
            domain_matches_certificate = False
            ssl_error_message = "Erro interno ao validar o domínio do certificado."

        status_msg = "Certificado Válido"
        if is_expired:
            status_msg = "Certificado EXPIRADO"

        elif not domain_matches_certificate:
            if "Hostname mismatch" in ssl_error_message:
                status_msg = "ALERTA: O domínio digitado NÃO corresponde ao certificado do site."
            elif "not valid for" in ssl_error_message:
                status_msg = f"ALERTA: O certificado não é válido para este domínio. ({ssl_error_message})"
            else:
                status_msg = "ATENÇÃO: Domínio não corresponde ao certificado!"

        return CertificateDetailsResponse(
            hostname=hostname,
            issuer=issuer,
            expiration_date=not_after.strftime('%Y-%m-%d %H:%M:%S %Z'),
            is_expired=is_expired,
            expires_in_days=expires_in_days,
            domain_matches_certificate=domain_matches_certificate,
            status_message=status_msg
        )
    
    except (socket.gaierror, ssl.SSLError, socket.timeout, asyncio.TimeoutError) as e:
        traceback.print_exc()
        friendly_detail = f"Não foi possível conectar ou estabelecer SSL/TLS com '{hostname}'."
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            friendly_detail += " O certificado do site não pôde ser verificado (pode estar inválido, autoassinado ou com problemas de confiança)."
        elif "hostname mismatch" in str(e).lower():
            friendly_detail += " O hostname do site não corresponde ao certificado (ALERTA DE SEGURANÇA!)."
        elif "timeout" in str(e).lower():
            friendly_detail += " A conexão expirou. O site pode estar lento ou inacessível."
        elif "no such host" in str(e).lower():
            friendly_detail += " O domínio não existe ou não pôde ser resolvido."
        else:
            friendly_detail += " O site pode estar inacessível ou não tem SSL/TLS válido."
            
        raise HTTPException(status_code=503, detail=friendly_detail)

    except Exception as e:
        traceback.print_exc() 
        raise HTTPException(
            status_code=500,
            detail=f"Ocorreu um erro interno inesperado ao verificar o certificado: {e}"
        )
    finally:
        if writer:
            writer.close()

def age_verifier(domain: str):
    w = whois.whois(domain)
    age = None

    if w.creation_date is not None:
        try:
            if isinstance(w.creation_date, list):
                creation = w.creation_date[0]
            else:
                creation = w.creation_date
        except Exception:
            creation = None

        if isinstance(creation, datetime):
            age = datetime.now() - creation
        elif isinstance(creation, str):
            try:
                creation = datetime.strptime(creation, '%Y-%m-%d %H:%M:%S')
                age = datetime.now() - creation
            except ValueError:
                pass

    if age is not None:
        if age.days <= 30:
            return f"{age.days} dias -> Muito suspeito"
        elif 30 < age.days < 365:
            return f"{age.days} dias -> Suspeito"
        elif age.days >= 365:
            return f"{age.days} dias -> Provavelmente seguro"
    
    return "Idade não encontrada"

def domain_verifier(hostname: str) -> bool:
    """Verifica se um hostname possui caracteres estranhos.
    
    Args:
        `hostname` (str): O hostname a ser verificado (ex: "www.google.com").

    Returns:
        `bool`: True se contiver caracteres estranhos (indicando suspeita), False caso contrário.
    """

    domain_without_www = hostname.replace("www.", "")
    
    if re.search(r'[^\w\.\-]', domain_without_www) or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        return True
    
    return False

def check_phishing(url: str, API_KEY: str) -> str:
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
        response = requests.post(url_post, json=body_post, timeout=5) # Adicionado timeout
        if response.status_code == 200 and response.json():
            return "URL na lista de sites de phishing"
        else:
            return "URL não encontrada na lista de sites de phishing do Google Safe Browse."
    except requests.exceptions.RequestException as e:
        return f"Erro ao verificar Google Safe Browse: {e}"
    except Exception as e:
        return f"Erro inesperado na verificação de phishing: {e}"

@app.get("/")
def read_root():
    return {"message": "API de Verificação de Phishing está rodando! Use o endpoint /check e /check_certificate."}

@app.post("/check")
async def check_url_endpoint(request: URLRequest):
    url = request.url

    hostname = None
    corrected_url = None

    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            corrected_url = "https://" + url
        else:
            corrected_url = url
            
        parsed_url = requests.utils.urlparse(corrected_url)
        hostname = parsed_url.hostname
        
        if not hostname:
            raise ValueError("Não foi possível extrair o hostname. URL inválida.")
        
    except ValueError as e:
        print(f"DEBUG: Erro ao extrair hostname da URL '{url}': {e}")
        traceback.print_exc()
        raise HTTPException(status_code=400, detail=f"Formato de URL inválido. Erro: {e}")
    
    except Exception as e:
        print(f"DEBUG: Erro inesperado ao extrair hostname da URL '{url}': {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Ocorreu um erro interno ao processar a URL: {e}")

    format_check = "Erro na verificação de formato."
    format_indicator = "danger"
    api_check = "Falha ao conectar ao servidor para Google Safe Browse."
    api_indicator = "danger"
    age_check = "Falha ao verificar idade do domínio."
    age_indicator = "danger"

    try:
        is_strange_format = domain_verifier(hostname) 
        if is_strange_format:
            format_check = "Aviso: A URL contém caracteres ou formato incomum, o que pode indicar phishing."
            format_indicator = "warning"
        else:
            format_check = "A URL parece normal em termos de formatação."
            format_indicator = "safe"

    except Exception as e:
        print(f"DEBUG: Erro na função domain_verifier para '{url}': {e}")

    try:
        api_check = check_phishing(corrected_url, API_KEY)
        
        if "URL na lista de sites de phishing" in api_check:
            api_indicator = "danger"
        elif "Falha ao conectar ao servidor para Google Safe Browse." in api_check or \
             "Erro ao verificar Google Safe Browse:" in api_check or \
             "Erro inesperado na verificação de phishing:" in api_check:
            api_indicator = "danger" 
        else:
            api_indicator = "safe"

    except Exception as e:
        print(f"DEBUG: Erro na função check_phishing para '{corrected_url}': {e}")
        traceback.print_exc()
        api_check = "Falha interna ao verificar Google Safe Browse."
        api_indicator = "danger"

    try:
        age_check = age_verifier(hostname)

        if "Muito suspeito" in age_check:
            age_indicator = "danger"
        elif "Suspeito" in age_check:
            age_indicator = "warning"
        elif "Idade não encontrada" in age_check:
            age_indicator = "not-found"
        else:
            age_indicator = "safe"
            
    except Exception as e:
        traceback.print_exc()

    response_data = {
        "hostname": hostname,
        "format_check": format_check,
        "format_indicator": format_indicator,
        "api_check": api_check,
        "api_indicator": api_indicator,
        "age_check": age_check,
        "age_indicator": age_indicator
    }

    return response_data

@app.post("/check_certificate", response_model=CertificateDetailsResponse)
async def check_certificate_endpoint(request: DomainCheckRequest):
    """
    Recebe um nome de domínio e retorna detalhes do seu certificado SSL/TLS,
    incluindo emissor, validade e correspondência de domínio.
    """
    return await perform_certificate_check(request.hostname)