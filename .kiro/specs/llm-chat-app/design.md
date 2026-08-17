# LLM Chat App — Design

## Architecture
- **app.py** — Streamlit entry point, handles UI and session state
- **chains/chat.py** — LangChain LCEL chain with chat history and streaming
- **prompts/system.py** — Default system prompt template

## Flow
1. User opens app → Streamlit initializes session state with empty message history
2. User types message → appended to history
3. History + message passed to LangChain chain → streamed response displayed
4. Response appended to history

## Key Decisions
- Use `ChatOpenAI` from langchain-openai with `streaming=True`
- Use `ChatPromptTemplate` with MessagesPlaceholder for history
- Session state stores list of `{"role": ..., "content": ...}` dicts
- Sidebar for system prompt and model selection
