# 🚀 API-Go: Autenticação JWT com Init‑Token e AgentAuth

Uma API em Go ultra‑segura, com duas camadas de token (init + access), protegida por Basic Auth (agentId/agentSecret) no ponto de partida — pronta pra escalar em Kubernetes, ECS ou onde você quiser.

---

## ✨ Features

- 🔐 **GET /token**: gera um _init token_ (curta expiração) via **Basic Auth** (agentId + agentSecret)
- 🔐 **POST /login**: protegido pelo _init token_, valida usuário/senha e devolve _access token_ JWT
- 🔒 **Todas as rotas em `/api/*`**: protegidas pelo _access token_
- ⚖️ **Stateless**: sem sessão no servidor, só o segredo JWT
- 🛠️ Fácil de rodar localmente, em Docker, Kubernetes ou CI/CD

---

## 🛠️ Pré‑requisitos

- Go ≥ 1.18
- Git
- (Opcional) [Docker](https://www.docker.com/)
- (Opcional) [GitHub CLI](https://cli.github.com/) `gh`

---

## 🚦 Instalação & Setup

1. Clone o repo e entre na pasta:
   ```bash
   git clone https://github.com/AlaxPaulo/api-go.git
   cd api-go
   ```
