import React, { useState } from "react";
import { checkUrl } from "./api";
import "./App.css"; // Arquivo de estilos para centralização e formatação

function App() {
    const [url, setUrl] = useState("");
    const [result, setResult] = useState(null);
    const [error, setError] = useState("");
    
    const handleCheck = async () => {
        if (!url.trim()) {
            setError("Por favor, insira uma URL.");
            return;
        }

        setError("");
        const data = await checkUrl(url);
        setResult({ url, ...data });
    };

    const getIndicator = (text) => {
        if (text.includes("Aviso")) {
            return <span className="indicator warning"></span>;
        } else if (text.includes("URL na lista")) {
            return <span className="indicator danger"></span>;
        } else {
            return <span className="indicator safe"></span>;
        }
    };    

    return (
        <div className="container">
            <h1 className="title">Ferramenta Anti-Phishing</h1>
            <div className="input-container">
                <input
                    type="text"
                    placeholder="Digite uma URL..."
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                />
                <button onClick={handleCheck}>Verificar</button>
                {error && <p className="error">{error}</p>}
            </div>

            {result && (
                <>
                    <table className="result-table">
                        <thead>
                            <tr>
                                <th>Link Verificado</th>
                                <th>Resultado</th>
                                <th>Indicador</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><a href={result.url} target="_blank" rel="noopener noreferrer">{result.url}</a></td>
                                <td>{result.format_check}</td>
                                <td>{getIndicator(result.format_check)}</td>
                            </tr>
                            <tr>
                                <td><a href={result.url} target="_blank" rel="noopener noreferrer">{result.url}</a></td>
                                <td>{result.api_check}</td>
                                <td>{getIndicator(result.api_check)}</td>
                            </tr>
                        </tbody>
                    </table>
                </>
            )}

            <div className="legend">
                <h3>Legenda:</h3>
                <p><span className="indicator safe"></span> URL segura</p>
                <p><span className="indicator warning"></span> Potencialmente suspeita</p>
                <p><span className="indicator danger"></span> URL identificada como phishing</p>
            </div>
        </div>
    );
}

export default App;
