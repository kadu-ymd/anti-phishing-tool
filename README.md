# Ferramenta Anti-Phishing (Anti-Phishing Tool)

A ferramenta desenvolvida nesse projeto tem como propósito facilitar o processo de descobrir se um site é ou não *phishing*.

Para isso, são analisados quatro pontos longo do procedimento:

- verificação de caracteres estranhos (números e caracteres especiais no domínio *i.e. www.g@0gle.com*);
- análise de certificado SSL/TLS;
- idade do domínio;
- presença na lista de sites conhecidos por *phishing* na API do **Google Safe Browsing**.

Dessa forma, cada um desses tópicos tem um indicativo dizendo o quão grave é o resultado, dependendo da resposta que a API que foi desenvolvida retorna.

O *frontend* (aplicação) foi feito utilizando **Vite** e o *backend* utilizando **FastAPI**, e a integração foi feita através de um *script* em **JavaScript**.

## Vite (frontend)

Para executar a ferramenta, é necessário ter uma chave da API do **Google Safe Browsing**, como descrito [nesse link](https://developers.google.com/safe-browsing/v4?hl=pt-br), e essa chave precisa estar em um arquivo `.env` na **raiz do projeto**, como demonstrado no `.env.example`.

Em seguida, partindo do princípio de que os pacotes do Node e Vite já estão instalados, executar os seguintes comandos:

``` bash
$ cd /anti-phishing-tool-app

$ npm run build
```

O serviço estará disponível no `localhost` na porta **5173**.

Antes de tudo, garanta que o ambiente virtual está pronto e ativo na **raiz do projeto**:

```bash
$ python -m venv env
```

No **Bash**:

```bash
$ source ./env/Scripts/activate
```

Ou no **PowerShell**:

```powershell
$ ./env/Scripts/Activate.ps1
```

## FastAPI (backend)

Para executar o servidor, é necessário instalar os pacotes presentes no arquivo `requirements.txt`:

```bash
$ cd /api

$ pip install -r requirements.txt
``` 

Em seguida, já na pasta `/api`:

```bash
fastapi run app/server.py --port 8000
```

Lembrando que o cliente (*frontend*) e o servidor (*backend*) precisam estar rodando simultaneamente para que a aplicação funcione corretamente.

Para ver o vídeo demonstrativo da aplicação funcionando, clique [nesse link](https://youtu.be/vwgup3RgQos).

---

### Desenvolvedor
- Carlos Eduardo Porciuncula Yamada
