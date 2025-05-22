// api.js
import axios from "axios";

const API_URL = "http://127.0.0.1:8000"; // Endereço do backend FastAPI

/**
 * Envia uma URL para o backend para verificações básicas de phishing.
 * @param {string} url - URL que será analisada.
 * @returns {Promise<Object>} - Dados retornados pelo backend.
 */
export const checkUrl = async (url) => {
    try {
        const response = await axios.post(`${API_URL}/check`, { url });
        return response.data;
    } catch (error) {
        console.error("Erro ao verificar a URL básica:", error);
        // Retorna um formato de erro consistente
        return { 
            hostname: new URL(url.startsWith('http') ? url : `https://${url}`).hostname,
            format_check: "Erro na verificação de formato.", format_indicator: "danger",
            api_check: "Falha ao conectar ao servidor para Google Safe Browse.", api_indicator: "danger",
            age_check: "Falha ao verificar idade do domínio.", age_indicator: "danger"
        };
    }
};

/**
 * Envia um hostname para o backend para verificação de certificado SSL/TLS.
 * @param {string} hostname - O nome do domínio a ser verificado.
 * @returns {Promise<Object>} - Dados retornados pelo backend sobre o certificado.
 */
export const checkCertificate = async (hostname) => {
    try {
        const response = await axios.post(`${API_URL}/check_certificate`, { hostname });
        return response.data;
    } catch (error) {
        console.error("Erro ao verificar o certificado:", error);
        // Retorna um formato de erro consistente para o certificado
        const errorDetail = error.response?.data?.detail || "Erro desconhecido ao obter certificado.";
        return {
            hostname: hostname,
            issuer: "N/A",
            expiration_date: "N/A",
            is_expired: true, // Se deu erro, assumimos que está "expirado" ou inválido
            expires_in_days: null,
            domain_matches_certificate: false,
            status_message: `Erro ao obter certificado: ${errorDetail}`,
        };
    }
};