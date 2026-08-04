import os
import time
import json
import jwt
import msal
import requests
import streamlit as st
from dotenv import load_dotenv
from portkey_ai import Portkey

# Load environment variables from .env file
load_dotenv()

# ==========================================
# ENVIRONMENT VARIABLES & VALIDATION
# ==========================================
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8501/")

PORTKEY_ORG_ID = os.getenv("PORTKEY_ORG_ID")
PORTKEY_WORKSPACE_SLUG = os.getenv("PORTKEY_WORKSPACE_SLUG")
PORTKEY_PROVIDER = os.getenv("PORTKEY_PROVIDER")
PORTKEY_BASE_URL = os.getenv("PORTKEY_BASE_URL", "https://aigw.portkey.ai/v1")
PORTKEY_DEFAULT_CONFIG_ID = os.getenv("PORTKEY_DEFAULT_CONFIG_ID")

PRIVATE_KEY_PATH = os.getenv("PRIVATE_KEY_PATH", "private_key.pem")
JWKS_PATH = os.getenv("JWKS_PATH", "jwks.json")

REQUIRED_ENV_VARS = [
    "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
    "PORTKEY_ORG_ID", "PORTKEY_WORKSPACE_SLUG", "PORTKEY_PROVIDER",
    "PORTKEY_DEFAULT_CONFIG_ID"
]
missing_vars = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]

if missing_vars:
    st.error(f"Missing required environment variables in .env: {', '.join(missing_vars)}")
    st.stop()

# ==========================================
# AVAILABLE MODELS LIST
# ==========================================
AVAILABLE_MODELS = [
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile",
    "qwen/qwen3.6-27b",
    "groq/compound",
    "groq/compound-mini",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b"
]

# ==========================================
# RSA KEYS & MSAL SETUP
# ==========================================
with open(PRIVATE_KEY_PATH, "r") as f:
    PRIVATE_KEY_PEM = f.read()

with open(JWKS_PATH, "r") as f:
    KID = json.load(f)["keys"][0]["kid"]

msal_app = msal.ConfidentialClientApplication(
    AZURE_CLIENT_ID,
    client_credential=AZURE_CLIENT_SECRET,
    authority=f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
)

# ==========================================
# PORTKEY JWT MINTING WITH LOCKED CONFIG
# ==========================================
def mint_portkey_jwt(user_email: str, user_sub: str, role: str, department: str) -> str:
    """
    Mints an RS256 JWT containing Portkey required claims, metadata, 
    and locks the PORTKEY_DEFAULT_CONFIG_ID inside the token payload.
    """
    now = int(time.time())
    payload = {
        "portkey_oid": PORTKEY_ORG_ID,
        "portkey_workspace": PORTKEY_WORKSPACE_SLUG,
        "scope": ["completions.write", "logs.view"],
        "email_id": user_email,
        "sub": user_sub,
        "iat": now,
        "exp": now + 3600,  # 1 hour validity
        "defaults": {
            # 🔒 Locks conditional routing/guardrails directly inside the signed JWT
            "config_id": PORTKEY_DEFAULT_CONFIG_ID,
            "metadata": {
                "email": user_email,
                "user_role": role,
                "department": department
            }
        }
    }
    headers = {"alg": "RS256", "typ": "JWT", "kid": KID}
    return jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256", headers=headers)

# ==========================================
# STREAMLIT UI & OAUTH HANDLING
# ==========================================
st.set_page_config(page_title="Enterprise Chat App", page_icon="🤖", layout="centered")

if "user" not in st.session_state:
    st.session_state.user = None
if "messages" not in st.session_state:
    st.session_state.messages = []

# OAuth Authorization Code Callback
query_params = st.query_params
if "code" in query_params and not st.session_state.user:
    auth_code = query_params["code"]
    
    result = msal_app.acquire_token_by_authorization_code(
        code=auth_code,
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI
    )
    
    if "id_token_claims" in result and "access_token" in result:
        claims = result["id_token_claims"]
        access_token = result["access_token"]
        
        # 1. Extract Email
        user_email = (
            claims.get("preferred_username") 
            or claims.get("email") 
            or claims.get("upn")
        )
        user_sub = claims.get("sub")
        user_name = claims.get("name", "User")
        
        # 2. Extract App Role
        assigned_roles = claims.get("roles", [])
        user_role = "Admin" if "Admin" in assigned_roles else "User"
        
        # 3. Fetch Department from Microsoft Graph API ($select parameter included)
        user_department = "General"  # Fallback
        try:
            graph_url = "https://graph.microsoft.com/v1.0/me?$select=department,displayName,mail,userPrincipalName"
            graph_response = requests.get(
                graph_url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=5
            )
            if graph_response.status_code == 200:
                profile_data = graph_response.json()
                user_department = profile_data.get("department") or "General"
        except Exception as err:
            st.warning(f"Could not fetch department from Graph API: {err}")
        
        # 4. Mint Portkey RS256 JWT containing Metadata and Locked Config ID
        portkey_jwt = mint_portkey_jwt(user_email, user_sub, user_role, user_department)
        
        st.session_state.user = {
            "name": user_name,
            "email": user_email,
            "role": user_role,
            "department": user_department,
            "portkey_jwt": portkey_jwt
        }
        st.query_params.clear()
        st.rerun()

# Unauthenticated View
if not st.session_state.user:
    st.title("🤖 Enterprise AI Chat Interface")
    st.info("Authenticate using your organization account to access the application.")
    
    auth_url = msal_app.get_authorization_request_url(
        scopes=["User.Read"],
        redirect_uri=REDIRECT_URI
    )
    st.link_button("🔑 Login with Azure AD", auth_url, type="primary")
    st.stop()

# ==========================================
# AUTHENTICATED CHAT INTERFACE
# ==========================================
user = st.session_state.user

# Sidebar Profile Details
st.sidebar.markdown("### User Profile")
st.sidebar.write(f"**Name:** {user['name']}")
st.sidebar.write(f"**Email:** {user['email']}")
st.sidebar.write(f"**Department:** {user['department']}")

if user["role"] == "Admin":
    st.sidebar.success("👑 Role: Administrator")
else:
    st.sidebar.info("👤 Role: Standard User")

st.sidebar.markdown("---")
st.sidebar.markdown("### LLM & Memory Controls")

# 1. Interactive Model Selection Dropdown
selected_model = st.sidebar.selectbox(
    "Select Model",
    options=AVAILABLE_MODELS,
    index=0
)

# 2. Custom System Prompt Text Area
system_prompt = st.sidebar.text_area(
    "System Prompt",
    value="You are a helpful, secure enterprise AI assistant.",
    height=80,
    help="Instructions passed to the model before processing user prompts."
)

# 3. Context History Window Slider
max_chat_history = st.sidebar.slider(
    "Max Context Messages",
    min_value=2,
    max_value=30,
    value=10,
    step=2,
    help="Limits how many recent chat messages are sent to Portkey to control context size and token costs."
)

st.sidebar.markdown("---")

# 4. Clear Chat History Button
if st.sidebar.button("🗑️ Clear Chat History", type="secondary"):
    st.session_state.messages = []
    st.rerun()

if st.sidebar.button("Logout"):
    st.session_state.user = None
    st.session_state.messages = []
    st.rerun()

# Main Chat Header
st.title("💬 Enterprise Chat")
st.caption(f"Gateway: `{PORTKEY_BASE_URL}` | Model: `{selected_model}` | Context Limit: `{max_chat_history}` msgs")

# Display Conversation History
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# User Prompt Input
if prompt := st.chat_input("Ask something..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Initialize Portkey Client using JWT
    portkey_client = Portkey(
        api_key=user["portkey_jwt"],
        base_url=PORTKEY_BASE_URL,
        provider=PORTKEY_PROVIDER
    )

    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        try:
            # Construct API payload:
            # 1. Add System Prompt at position 0 (if provided)
            payload_messages = []
            if system_prompt.strip():
                payload_messages.append({"role": "system", "content": system_prompt.strip()})

            # 2. Append the last 'max_chat_history' messages from session state
            recent_messages = st.session_state.messages[-max_chat_history:]
            for msg in recent_messages:
                payload_messages.append({"role": msg["role"], "content": msg["content"]})

            response = portkey_client.chat.completions.create(
                model=selected_model,
                messages=payload_messages,
                max_tokens=512
            )
            reply = response.choices[0].message.content
            message_placeholder.markdown(reply)
            st.session_state.messages.append({"role": "assistant", "content": reply})
        except Exception as e:
            st.error(f"Portkey Gateway Error: {str(e)}")