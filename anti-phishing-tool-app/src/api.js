import axios from "axios";

const API_URL = "http://127.0.0.1:8000"; // Endereço do backend FastAPI

/**
 * Envia uma URL para o backend para verificação de phishing.
 * @param {string} url - URL que será analisada.
 * @returns {Promise<Object>} - Dados retornados pelo backend.
 */
export const checkUrl = async (url) => {
    try {
        const response = await axios.post(`${API_URL}/check`, { url });
        return response.data;
    } catch (error) {
        console.error("Erro ao verificar a URL:", error);
        return { format_check: "Erro na verificação.", api_check: "Falha ao conectar ao servidor." };
    }
};
