# LLM Chat App — Requirements

## Goal
Build a conversational chat application powered by OpenAI via LangChain with a Streamlit UI.

## Functional Requirements
1. User can type a message and receive a response from the LLM
2. Conversation history is maintained within the session
3. Streaming responses for real-time output
4. System prompt is configurable via the sidebar
5. Model selection (gpt-4o, gpt-4o-mini) via sidebar dropdown

## Non-Functional Requirements
- API key loaded from .env, never exposed in the UI
- Graceful error handling if the API key is missing or invalid
- Clean, minimal UI
