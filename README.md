🛡️ ShieldProxy

Enterprise-Grade, 4-Layer Asynchronous Security Middleware for LLMs.

ShieldProxy is a high-performance, asynchronous API gateway built on FastAPI.It acts as a 
transparent, drop-in replacement middleware between client applications and Large Language 
Model (LLM) providers (e.g., Groq, OpenAI, Anthropic).

By intercepting traffic at the network layer, ShieldProxy sanitizes inputs, evaluates prompts 
for malicious intent, enforces system-level constraints, and prevents data exfiltration—all in 
real-time with minimal latency overhead.


🏗️ Architecture Overview
ShieldProxy utilizes a Bring Your Own Key (BYOK) architecture. It mimics the standard 
OpenAI v1/chat/completions endpoint schema, allowing existing applications to route 
traffic through the proxy without altering their underlying application logic or frontend code.

Routing and provider selection are handled dynamically per request via custom HTTP 
headers, making the proxy completely provider-agnostic.

🔐 The 4-Layer Defense Engine
ShieldProxy processes every request and response through a sequential, fail-fast security 
pipeline:

Layer 1: Input Sanitization
 -> Normalizes character encodings.
 -> Strips invisible control characters, zero-width spaces, and bypass artifacts often used in prompt obfuscation.
 -> Mitigates basic token-smuggling attacks.
 
 Layer 2: AI Policy Scanner (Prompt Injection Defense)
 -> Semantically analyzes the incoming prompt using a localized or fast-path AI evaluator.
 -> Detects role-play jailbreaks, system prompt overrides (e.g., "Ignore previous instructions"), and complex injection payloads.
 -> Rejects requests that exceed the configured risk threshold.
 
 Layer 3: Context Anchoring
 -> Enforces strict boundaries on the LLM's operational scope.
 -> Injects invisible, immutable system constraints into the prompt payload before it reaches the external provider, preventing context drift and hallucination vectors.
 
 Layer 4: Data Loss Prevention (DLP)
 -> Intercepts the inbound response from the LLM provider before it reaches the client.
 -> Scans the payload for sensitive data (PII, API keys, internal network topologies).
 -> Redacts or blocks the response entirely if data exfiltration is detected.
 
 
 🚀 Installation
 Prerequisites:
 ->Python 3.10+
 -> pip package manager 
 
 1. Clone the repository
  git clone [https://github.com/yourusername/shieldproxy-core.git](https://github.com/yourusername/shieldproxy-core.git)
  cd shieldproxy-core

2. Install dependencies
   pip install -r requirements.txt

   
3. Environment Configuration
   Copy the example environment file and define your fallback variables:
   cp .env.example .env
Note: These environment variables act as the default fallback. They can be dynamically overridden per-request using HTTP headers.

4. Start the Gateway
   uvicorn server:app --host 0.0.0.0 --port 8000

   
💻 API Reference & Usage
ShieldProxy exposes a single, unified endpoint: POST /v1/chat/completions.

Dynamic Routing (BYOK Headers)
To route traffic dynamically, pass the following custom headers in your HTTP request. If omitted, the server defaults to the values in your .env file.



Header                          Description                                 Example

X-Target-Url                    The base API URL of the LLM provider.        https://api.groq.com/openai/v1/chat/completions

X-Target-Model                  The specific model ID to invoke.             llama-3.1-8b-instant

X-Target-Key                    The API authorization key for the provider.   gsk_...



Example cURL Request

curl -X POST "http://localhost:8000/v1/chat/completions" \
     -H "Content-Type: application/json" \
     -H "X-Target-Url: [https://api.groq.com/openai/v1/chat/completions](https://api.groq.com/openai/v1/chat/completions)" \
     -H "X-Target-Model: llama-3.1-8b-instant" \
     -H "X-Target-Key: YOUR_API_KEY" \
     -d '{
           "messages": [
             {"role": "user", "content": "Hello, system!"}
           ]
         }'

         
Security Responses
If a request fails any layer of the security engine, ShieldProxy instantly terminates the connection (saving downstream API costs) and returns a standard HTTP 400/403 with a JSON error payload:

{
  "error": "AI Guard blocked: INJECTION (confidence: 99.35%)"
}


📂 Project Structureshieldproxy-core/
├── layers/                  # The 4-Layer Defense Engine modules
│   ├── sanitizer.py         # Layer 1: Normalization
│   ├── policy_engine.py     # Layer 2: Injection detection
│   ├── context_manager.py   # Layer 3: Boundary enforcement
│   └── output_guard.py      # Layer 4: DLP & PII scanning
├── ruleFile.yaml            # Configurable security thresholds
├── server.py                # FastAPI asynchronous gateway
├── requirements.txt         # Production dependencies
└── .env.example             # Environment template
