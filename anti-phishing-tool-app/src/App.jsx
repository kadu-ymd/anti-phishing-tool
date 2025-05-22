// App.jsx
import React, { useState } from "react";
import { checkUrl, checkCertificate } from "./api"; // Importa a nova função checkCertificate
import "./App.css";

function App() {
    const [url, setUrl] = useState("");
    const [results, setResults] = useState([]); // Agora 'results' é um array para múltiplas linhas
    const [error, setError] = useState("");
    const [isLoading, setIsLoading] = useState(false); // Novo estado para loading

    const handleCheck = async () => {
        if (!url.trim()) {
            setError("Por favor, insira uma URL.");
            return;
        }

        setError("");
        setResults([]); // Limpa resultados anteriores
        setIsLoading(true); // Ativa o loading

        try {
            // Extrai o hostname da URL para a verificação do certificado
            let hostname;
            try {
                const parsedUrl = new URL(url.startsWith("http") ? url : `https://${url}`);
                hostname = parsedUrl.hostname;
            } catch (e) {
                setError("URL inválida. Certifique-se de que é um formato válido (ex: google.com ou https://google.com).");
                setIsLoading(false);
                return;
            }

            // 1. Chamada para as verificações existentes (formato, api, idade)
            const basicChecksData = await checkUrl(url); // Agora retorna indicadores de status

            // 2. Chamada para a verificação de certificado
            const certData = await checkCertificate(hostname);

            // Monta o array de resultados para exibição
            const newResults = [
                {
                    link: url,
                    check: "Formatação da URL",
                    outcome: basicChecksData.format_check,
                    indicator: basicChecksData.format_indicator,
                },
                {
                    link: url,
                    check: "Google Safe Browse",
                    outcome: basicChecksData.api_check,
                    indicator: basicChecksData.api_indicator,
                },
                {
                    link: url,
                    check: "Idade do Domínio",
                    outcome: basicChecksData.age_check,
                    indicator: basicChecksData.age_indicator,
                },
                {
                    link: hostname, // Pode ser o hostname aqui, já que o certificado é do domínio
                    check: "Certificado SSL/TLS",
                    outcome: certData.status_message, // A mensagem de status já é bem completa
                    indicator: getCertIndicator(certData), // Nova função para indicador do certificado
                    details: certData // Guarda os detalhes completos para talvez exibir mais tarde
                }
            ];
            
            setResults(newResults);

        } catch (err) {
            setError(err.message || "Ocorreu um erro ao verificar a URL.");
            setResults([]);
        } finally {
            setIsLoading(false); // Desativa o loading
        }
    };

    // Função auxiliar para determinar o indicador do certificado
    const getCertIndicator = (certData) => {
        if (certData.is_expired) {
            return "danger"; // Vermelho
        } else if (!certData.domain_matches_certificate) {
            return "warning"; // Laranja
        } else if (certData.status_message.includes("Erro")) {
            return "danger"; // Se houve erro ao obter, é vermelho também
        } else {
            return "safe"; // Verde
        }
    }; 

    return (
        <div className="container">
            <h1 className="title">Ferramenta Anti-Phishing</h1>
            <div className="input-container">
                <input
                    type="text"
                    placeholder="Digite uma URL (ex: google.com ou https://google.com)..."
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                />
                <button onClick={handleCheck} disabled={isLoading}>
                    {isLoading ? "Verificando..." : "Verificar"}
                </button>
                {error && <p className="error">{error}</p>}
            </div>

            {isLoading && <p>Carregando verificações...</p>} {/* Indicador de carregamento */}

            {results.length > 0 && ( // Mostra a tabela apenas se houver resultados
                <>
                    <table className="result-table">
                        <thead>
                            <tr>
                                <th>Link Verificado</th>
                                <th>Verificação</th> {/* Nova coluna para tipo de verificação */}
                                <th>Resultado</th>
                                <th>Indicador</th>
                            </tr>
                        </thead>
                        <tbody>
                            {results.map((item, index) => (
                                <tr key={index}>
                                    <td>
                                        <a 
                                            href={item.link.startsWith("http") ? item.link : `https://${item.link}`} 
                                            target="_blank" 
                                            rel="noopener noreferrer"
                                        >
                                            {item.link}
                                        </a>
                                    </td>
                                    <td>{item.check}</td> {/* Nome da verificação */}
                                    <td>{item.outcome}</td>
                                    <td><div className="container-indicator"><span className={`indicator ${item.indicator}`}></span></div></td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </>
            )}

            <div className="legend">
                <h3>Legenda:</h3>
                <p><span className="indicator safe"></span> URL segura</p>
                <p><span className="indicator warning"></span> Potencialmente suspeita</p>
                <p><span className="indicator danger"></span> URL identificada como phishing</p>
                <p><span className="indicator not-found"></span> Informação não encontrada/erro</p>
            </div>
        </div>
    );
}

export default App;