document.getElementById("urlForm").addEventListener("submit", function(event) {
    event.preventDefault();

    const url = document.getElementById("urlInput").value;
    const resultDiv = document.getElementById("result");

    resultDiv.innerHTML = "<p>Verificando...</p>";

    fetch("http://localhost:8000/check", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error("Erro na resposta do servidor");
        }
        return response.json();
    })
    .then(data => {
        resultDiv.innerHTML = `
            <h3>Resultados:</h3>
            <p><strong>Análise de Formato:</strong> ${data.format_check}</p>
            <p><strong>Verificação via API:</strong> ${data.api_check}</p>
        `;
    })
    .catch(error => {
        console.error("Erro:", error);
        resultDiv.innerHTML = "<p style='color:red;'>Erro ao verificar URL.</p>";
    });
});