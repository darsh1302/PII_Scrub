# Requirements Document

## Introduction

The PII Scrubbing Agent is an autonomous AI agent that detects, classifies, and remediates Personally Identifiable Information and other sensitive data across multiple input sources. The agent uses a LangGraph-based reasoning loop (ReAct pattern) where GPT-4o serves as the brain — reasoning about user requests, planning multi-step approaches, selecting and invoking tools, and reporting results conversationally.

Users interact with the agent through a Streamlit chat interface using natural language. They can say things like "Scan this log file for PII", "Check our CloudWatch logs from the last hour for credentials", or "What sensitive data is in this text?" The agent understands intent, asks clarifying questions when needed, plans its approach, executes using available tools, and reports findings.

The agent's core architecture:
- **BRAIN** (GPT-4o via LangGraph): Reasons, plans, decides which tools to use, interprets results, chains actions
- **TOOLS**: Presidio Analyzer, spaCy NER, file readers, AWS CloudWatch client, Windows Event Log reader, anonymization operators, profile resolver
- **MEMORY**: Session-scoped conversation history, user preferences, previously scanned sources, detection patterns
- **STATE MACHINE**: IDLE → THINKING → PLANNING → EXECUTING → ANALYZING → REPORTING → WAITING_FOR_INPUT

The domain model remains:
- SOURCE tells the agent: where should it get the data?
- PROFILE tells the agent: what sensitive information should it look for?
- DETECTION TOOLS tell the agent: what did they find?
- POLICY tells the agent: what should happen to detected entities?
- DESTINATION tells the agent: how restrictive should the action be?

These concerns remain independently extensible and are presented to the agent as configurable tool parameters.

## Glossary

- **Agent**: The LangGraph-based autonomous reasoning system that orchestrates PII detection and remediation using the ReAct pattern
- **Agent_Brain**: The GPT-4o LLM that serves as the reasoning, planning, and decision-making core of the Agent
- **Agent_State**: The current operational phase of the Agent — one of IDLE, THINKING, PLANNING, EXECUTING, ANALYZING, REPORTING, or WAITING_FOR_INPUT
- **Tool**: A callable capability the Agent can invoke during execution — includes detection tools, source adapters, anonymization operators, and utility functions
- **Tool_Registry**: The collection of all available tools registered with the Agent, each with a name, description, and input schema
- **Reasoning_Loop**: The iterative ReAct cycle where the Agent observes context, thinks about what to do, acts by calling a tool, and observes the result before deciding next steps
- **Plan**: A structured sequence of steps the Agent formulates before executing a complex request
- **Session_Memory**: The conversational context maintained within a user session including chat history, user preferences, scanned sources, and detection patterns
- **Chat_Interface**: The Streamlit-based conversational UI where users interact with the Agent via natural language
- **Presidio_Tool**: The tool wrapping Microsoft Presidio Analyzer for rule-based entity detection
- **SpaCy_Tool**: The tool wrapping spaCy NLP models for named entity recognition
- **File_Reader_Tool**: The tool for reading and streaming content from local files
- **CloudWatch_Tool**: The tool for retrieving log events from AWS CloudWatch
- **EventLog_Tool**: The tool for reading Windows Event Log entries
- **Anonymizer_Tool**: The tool wrapping Presidio Anonymizer for applying scrub actions to detected entities
- **Profile_Resolver_Tool**: The tool that resolves which detection rules and scrub actions apply based on the active profile configuration
- **Entity**: A detected sensitive item characterized by type, position, confidence score, text value, and detection source
- **Confidence_Threshold**: A numeric value between 0.0 and 1.0 that determines the minimum detection confidence for an entity to be reported
- **Scrub_Action**: The action performed on a detected sensitive entity — one of ALLOW, REPLACE, MASK, HASH, TOKENIZE, REDACT, or BLOCK
- **Source_Type**: An identifier that determines which source tool the Agent selects (TEXT, FILE, APPLICATION_LOG, AWS_CLOUDWATCH, WINDOWS_EVENT_LOG)
- **Normalized_Event**: A common internal representation of data regardless of origin source
- **Scrub_Profile**: A configuration defining which sensitive-data categories are applicable and what action to take for each (DEFAULT_PII, HEALTHCARE, FINANCIAL, PAYMENT_PCI, etc.)
- **Base_Security_Profile**: Mandatory rules for authentication credentials and secrets that execute regardless of the selected industry profile
- **Default_PII_Profile**: The baseline PII detection rules used when no Scrub_Profile is explicitly specified
- **Industry_Profile**: A specialized set of sensitive-data detection rules extending the Default_PII_Profile
- **Policy_Engine**: The logic the Agent invokes to resolve which Scrub_Action to apply based on source, profile, entity type, and destination
- **Token_Vault**: An isolated secure store maintaining reversible tokenization mappings

## Requirements

### Requirement 1: Agent Reasoning Loop

**User Story:** As a user, I want the PII scrubbing system to operate as an autonomous agent that reasons about my requests and decides how to fulfill them, so that I can interact naturally without knowing the underlying tools.

#### Acceptance Criteria

1. THE Agent SHALL implement a ReAct (Reason + Act) loop using LangGraph where each iteration consists of: observe context, reason about next step, select and invoke a tool, observe tool result
2. THE Agent SHALL use GPT-4o as the Agent_Brain for all reasoning and planning decisions
3. WHEN a user submits a request, THE Agent SHALL enter the THINKING state to analyze intent before taking action
4. THE Agent SHALL support multi-step execution where the output of one tool invocation informs the next reasoning step
5. THE Agent SHALL terminate its reasoning loop when the user's goal is fulfilled or when the Agent determines it cannot proceed without additional user input
6. IF a tool invocation fails, THEN THE Agent SHALL reason about the failure, attempt an alternative approach, or report the issue to the user with a suggested resolution

### Requirement 2: Agent Planning and Decision Making

**User Story:** As a user, I want the agent to plan its approach before executing, so that complex requests are handled systematically and I can understand what the agent intends to do.

#### Acceptance Criteria

1. WHEN the Agent receives a complex request involving multiple sources or steps, THE Agent SHALL formulate a Plan before beginning execution
2. THE Agent SHALL decide which source tool to use based on the user's request context (file path implies File_Reader_Tool, mention of CloudWatch implies CloudWatch_Tool, raw text implies direct analysis)
3. THE Agent SHALL decide what detection sensitivity is appropriate based on explicit user instructions or session preferences
4. THE Agent SHALL decide which Scrub_Profile to apply based on user instructions, previously stated preferences, or by asking the user
5. THE Agent SHALL present its Plan to the user in conversational form before executing when the request is ambiguous or high-impact
6. WHEN the Agent encounters ambiguity in a request, THE Agent SHALL ask clarifying questions rather than making assumptions about user intent

### Requirement 3: Conversational Chat Interface

**User Story:** As a user, I want to interact with the agent through natural language chat, so that I can request PII scanning, ask questions, and receive results conversationally.

#### Acceptance Criteria

1. THE Chat_Interface SHALL provide a Streamlit-based chat UI where users send messages and receive agent responses in a threaded conversation
2. THE Chat_Interface SHALL display the Agent_State (THINKING, SCANNING, ANALYZING, etc.) as a status indicator during processing
3. THE Chat_Interface SHALL stream agent responses as they are generated for real-time feedback
4. THE Chat_Interface SHALL support natural language requests including: "Scan this file for PII", "Check CloudWatch logs from the last hour", "What sensitive data is in this text?", "Redact all PII and give me a clean version"
5. THE Chat_Interface SHALL display detected entities, statistics, and scrubbed output inline within the conversation
6. THE Chat_Interface SHALL allow users to paste text directly into chat messages for immediate analysis
7. THE Chat_Interface SHALL provide file upload capability within the chat for document scanning

### Requirement 4: Agent State Machine

**User Story:** As a user, I want visibility into what the agent is currently doing, so that I understand whether it is thinking, scanning, or waiting for my input.

#### Acceptance Criteria

1. THE Agent SHALL maintain an Agent_State that transitions through: IDLE, THINKING, PLANNING, EXECUTING, ANALYZING, REPORTING, and WAITING_FOR_INPUT
2. WHEN the Agent enters a new state, THE Chat_Interface SHALL display the current state to the user
3. THE Agent SHALL transition to THINKING when a new user message is received
4. THE Agent SHALL transition to PLANNING when a multi-step approach is formulated
5. THE Agent SHALL transition to EXECUTING when invoking a tool
6. THE Agent SHALL transition to ANALYZING when interpreting tool results
7. THE Agent SHALL transition to REPORTING when presenting findings to the user
8. THE Agent SHALL transition to WAITING_FOR_INPUT when it requires user clarification or confirmation
9. THE Agent SHALL transition to IDLE when conversation is complete and no action is pending

### Requirement 5: Session Memory and Context

**User Story:** As a user, I want the agent to remember our conversation context and my preferences within a session, so that I do not need to repeat configuration for every request.

#### Acceptance Criteria

1. THE Agent SHALL maintain Session_Memory containing: full conversation history, user-stated preferences, previously scanned sources, and detection pattern summaries
2. WHEN a user has previously specified a preferred Scrub_Profile in the session, THE Agent SHALL apply that profile to subsequent requests unless overridden
3. WHEN a user references a previously scanned file ("scan that file again" or "what did you find earlier"), THE Agent SHALL resolve the reference from Session_Memory
4. THE Agent SHALL use Session_Memory to avoid repeating questions the user has already answered
5. THE Session_Memory SHALL be scoped to the current user session and SHALL NOT persist across browser sessions by default
6. THE Agent SHALL create a distinct Session_Context per user session owning the content store, token vault, allowlist, and temporary directory, and these SHALL NOT be shared across sessions even when a single server process serves multiple sessions
7. THE Content_Handles SHALL be unguessable and namespaced to their issuing session so that a handle issued in one session cannot be resolved in another
8. THE Agent SHALL redact detected sensitive values from the stored conversation transcript after the turn that produced them, replacing them with a Content_Handle reference
9. THE Agent SHALL apply a rolling window to conversation history so that transcript size and token cost remain bounded across a long session
10. THE Agent SHALL summarize its understanding of user preferences when asked ("What are my current settings?")

### Requirement 6: Tool Registry and Invocation

**User Story:** As a developer, I want the agent's tools defined in a registry with clear schemas, so that the agent can discover, select, and invoke tools dynamically.

#### Acceptance Criteria

1. THE Agent SHALL maintain a Tool_Registry containing all available tools with their names, descriptions, input schemas, and output schemas
2. THE Agent_Brain SHALL select tools from the Tool_Registry based on the current reasoning step and user intent
3. EACH tool invocation SHALL be logged with: tool name, input parameters (excluding sensitive content), execution duration, and success/failure status
4. THE Tool_Registry SHALL be extensible — adding a new tool SHALL NOT require modification to the Agent's core reasoning loop
5. THE Agent SHALL validate tool input parameters against the schema before invocation
6. IF a required tool is unavailable (missing API key, service down), THEN THE Agent SHALL inform the user and suggest alternatives

### Requirement 7: Presidio Detection Tool

**User Story:** As a user, I want the agent to have access to rule-based PII detection, so that common PII types are identified quickly and without API costs.

#### Acceptance Criteria

1. THE Presidio_Tool SHALL detect entities of the following types: PERSON, EMAIL_ADDRESS, PHONE_NUMBER, US_SSN, CREDIT_CARD, LOCATION, IP_ADDRESS, DATE_TIME, US_PASSPORT, US_DRIVER_LICENSE, MEDICAL_LICENSE, IBAN_CODE, and US_BANK_NUMBER
2. THE Presidio_Tool SHALL accept a Confidence_Threshold parameter and return only entities with a detection score equal to or above the specified threshold
3. THE Presidio_Tool SHALL return each detected Entity with its type, start position, end position, confidence score, and matched text
4. WHEN no PII is present in the submitted text, THE Presidio_Tool SHALL return an empty result set
5. THE Presidio_Tool SHALL accept an optional entity type filter to restrict detection to specified types

### Requirement 8: SpaCy NER Tool

**User Story:** As a user, I want the agent to leverage NLP-based entity recognition for contextual detection that pattern matching alone would miss.

#### Acceptance Criteria

1. THE SpaCy_Tool SHALL perform named entity recognition using spaCy language models
2. THE SpaCy_Tool SHALL detect contextual entities including: PERSON names, ORGANIZATION names, LOCATION references, and DATE expressions
3. THE SpaCy_Tool SHALL return entities with type, start position, end position, and confidence score
4. THE Agent SHALL use the SpaCy_Tool in combination with the Presidio_Tool when comprehensive detection is requested
5. IF the spaCy model fails to load, THEN THE SpaCy_Tool SHALL report the failure to the Agent, which SHALL inform the user of degraded detection capability

### Requirement 9: File Reader Tool

**User Story:** As a user, I want the agent to read files from disk when I provide a file path, so that I can scan log files, documents, and data exports for PII.

#### Acceptance Criteria

1. THE File_Reader_Tool SHALL accept a local file path and return the file content for analysis
2. THE File_Reader_Tool SHALL support file types: .txt, .log, .json, .jsonl, .csv, and .xml
3. THE File_Reader_Tool SHALL support buffered/streaming reads for large files without loading the entire file into memory
4. THE File_Reader_Tool SHALL validate that the requested file exists and is accessible before reading
5. THE File_Reader_Tool SHALL accept paths only within an operator-configured allowlist of scan roots and SHALL refuse any path resolving outside those roots
6. THE File_Reader_Tool SHALL refuse paths matching a sensitive-path denylist regardless of scan root, including `.env*`, `id_*`, `*.pem`, `*.pfx`, `credentials`, `.aws/**`, `.ssh/**`, and `.kube/**`
7. THE File_Reader_Tool SHALL resolve the canonical real path AFTER opening the file handle and SHALL verify the resolved path remains within an allowed scan root, thereby rejecting symbolic-link escape and time-of-check-to-time-of-use substitution
8. THE File_Reader_Tool SHALL perform all metadata checks against the open file handle rather than against the path
9. IF a path traversal pattern is detected in the file path, THEN THE File_Reader_Tool SHALL reject the request and return an error to the Agent
10. THE File_Reader_Tool SHALL refuse non-regular files including FIFOs, device files, and sockets
11. THE File_Reader_Tool SHALL parse XML using a hardened parser with external entity resolution, DTD processing, and entity expansion disabled
12. THE File_Reader_Tool SHALL enforce maximum nesting depth and maximum node count when parsing structured formats
13. THE File_Reader_Tool SHALL chunk on structural boundaries and SHALL size chunk overlap to at least the longest pattern span the active profile can match
14. THE File_Reader_Tool SHALL report file metadata (size, type, line count) to the Agent for planning purposes

### Requirement 10: AWS CloudWatch Tool

**User Story:** As a user, I want the agent to pull logs from AWS CloudWatch when I ask about cloud application logs, so that I can scan production logs for sensitive data leakage.

#### Acceptance Criteria

1. THE CloudWatch_Tool SHALL accept configuration including: AWS region, log group, optional log stream, optional start time, and optional end time
2. THE CloudWatch_Tool SHALL retrieve log events and return them as normalized content for analysis
3. THE CloudWatch_Tool SHALL preserve relevant operational metadata including timestamp, log group, log stream, and event ID
4. THE CloudWatch_Tool SHALL use least-privilege IAM permissions for AWS access
5. THE CloudWatch_Tool SHALL support batched retrieval of CloudWatch events
6. THE CloudWatch_Tool SHALL avoid storing an additional unsanitized copy of retrieved events
7. IF AWS credentials are missing or invalid, THEN THE CloudWatch_Tool SHALL return a descriptive error to the Agent

### Requirement 11: Windows Event Log Tool

**User Story:** As a user, I want the agent to read Windows Event Logs when I ask about system events, so that sensitive data in machine logs can be detected.

#### Acceptance Criteria

1. THE EventLog_Tool SHALL support reading from channels: Application, System, Security, and supported custom event channels
2. THE EventLog_Tool SHALL preserve operational event metadata including: Event ID, Provider, Level, Computer, Timestamp, Process ID, and Thread ID
3. THE EventLog_Tool SHALL return the event message and configurable event attributes for analysis
4. THE EventLog_Tool SHALL accept optional filters for time range, event level, and provider
5. IF the requested event channel is inaccessible, THEN THE EventLog_Tool SHALL return a permission error to the Agent

### Requirement 12: Anonymizer Tool

**User Story:** As a user, I want the agent to redact, mask, or transform detected PII using my preferred method, so that I receive a clean version of my data.

#### Acceptance Criteria

1. THE Anonymizer_Tool SHALL support Scrub_Actions: REPLACE, MASK, HASH, TOKENIZE, REDACT, and BLOCK
2. WHEN the action is REPLACE, THE Anonymizer_Tool SHALL substitute each detected entity with a type label in the format `[ENTITY_TYPE]`
3. WHEN the action is MASK, THE Anonymizer_Tool SHALL overwrite each detected entity with asterisk characters
4. WHEN the action is HASH, THE Anonymizer_Tool SHALL replace each detected entity with its salted SHA-256 hash digest
5. WHEN the action is TOKENIZE, THE Anonymizer_Tool SHALL replace the entity with a surrogate identifier and store the mapping in the Token_Vault
6. WHEN the action is REDACT, THE Anonymizer_Tool SHALL remove the entity entirely from the output
7. WHEN any entity resolves to BLOCK, THE Anonymizer_Tool SHALL produce no sanitized artifact at all and SHALL return a findings report with a BLOCKED_ARTIFACT refusal — BLOCK SHALL be observably distinct from REDACT
8. THE Anonymizer_Tool SHALL apply transformations in descending order of entity start offset so that unprocessed offsets remain valid as replacement lengths change
9. THE Anonymizer_Tool SHALL receive entity positions from the deterministic scan record and SHALL NOT accept entity positions supplied by the Agent_Brain
10. AFTER applying transformations, THE Anonymizer_Tool SHALL re-scan the output using the same profile, and IF any entity is still detected THEN it SHALL withhold the artifact, return a RESIDUAL_PII_DETECTED refusal, and record the condition as a defect
11. THE Anonymizer_Tool SHALL offer an artifact for export only when the verification re-scan detects zero residual entities
12. WHEN no entities are detected, THE Anonymizer_Tool SHALL return the original text unchanged

### Requirement 13: Profile Resolver Tool

**User Story:** As a developer, I want the agent to resolve which detection rules and actions apply based on the active profile, so that industry-appropriate handling is applied automatically.

#### Acceptance Criteria

1. THE Profile_Resolver_Tool SHALL accept a profile name and return the effective detection rules and per-entity Scrub_Actions
2. THE Profile_Resolver_Tool SHALL resolve profile inheritance: every Industry_Profile inherits BASE_SECURITY plus DEFAULT_PII rules
3. THE Profile_Resolver_Tool SHALL support combining multiple profiles and resolving conflicts using the more restrictive action
4. THE default action priority SHALL be: BLOCK > REDACT > TOKENIZE > HASH > MASK > REPLACE > ALLOW
5. IF an invalid profile name is supplied, THEN THE Profile_Resolver_Tool SHALL return an INVALID_PROFILE error to the Agent
6. THE Profile_Resolver_Tool SHALL read profile definitions from structured configuration (YAML or equivalent)

### Requirement 14: Autonomous Action Chaining

**User Story:** As a user, I want the agent to autonomously chain multiple steps when fulfilling my request, so that I get complete results without manually triggering each step.

#### Acceptance Criteria

1. THE Agent SHALL autonomously chain actions when a user request implies multiple steps (e.g., "scan this file and give me a redacted version" implies: read file → detect PII → classify severity → anonymize → output clean version)
2. THE Agent SHALL report intermediate progress during multi-step execution ("Found 12 entities, now applying redaction...")
3. THE Agent SHALL offer follow-up actions after completing a scan ("I found 8 PII entities. Would you like me to redact them, show details, or export a clean version?")
4. THE Agent SHALL support the full chain: detect → classify severity → suggest remediation → offer to redact → export clean version
5. WHEN the Agent determines that a follow-up action requires user confirmation (e.g., overwriting a file), THE Agent SHALL transition to WAITING_FOR_INPUT and ask before proceeding

### Requirement 15: Natural Language Understanding for PII Tasks

**User Story:** As a user, I want the agent to understand varied ways of asking for PII scanning, so that I do not need to use specific commands or syntax.

#### Acceptance Criteria

1. THE Agent SHALL interpret intent from natural language including variations: "find PII", "scan for sensitive data", "check for personal information", "are there any secrets in this?", "scrub this file", "anonymize this text"
2. THE Agent SHALL extract parameters from natural language: file paths, time ranges ("last hour", "yesterday"), profile hints ("this is healthcare data"), and action preferences ("just mask the emails")
3. THE Agent SHALL handle ambiguous requests by asking targeted clarifying questions
4. THE Agent SHALL support follow-up commands that reference previous context: "now do the same for this file", "use stricter settings", "show me just the emails you found"
5. WHEN the user provides raw text without explicit instructions, THE Agent SHALL interpret it as a request to scan that text for PII

### Requirement 16: Agent Error Handling and Recovery

**User Story:** As a user, I want the agent to handle errors gracefully and explain what went wrong in plain language, so that I can resolve issues or adjust my request.

#### Acceptance Criteria

1. IF a tool invocation fails, THEN THE Agent SHALL explain the failure to the user in conversational language and suggest corrective actions
2. IF AWS credentials are missing when CloudWatch scanning is requested, THEN THE Agent SHALL explain what credentials are needed and how to configure them
3. IF a file cannot be read, THEN THE Agent SHALL explain the specific issue (not found, permission denied, unsupported format) and suggest alternatives
4. THE Agent SHALL NOT expose stack traces, internal error codes, or raw exception messages to the user
5. IF the Agent_Brain encounters an unrecoverable error, THEN THE Agent SHALL gracefully inform the user and reset to IDLE state
6. THE Agent SHALL maintain conversation continuity after errors — a failed tool invocation SHALL NOT terminate the session

### Requirement 17: Environment and API Key Management

**User Story:** As a developer, I want API keys loaded securely from environment variables, so that secrets are not exposed in source code.

#### Acceptance Criteria

1. THE Agent SHALL load the OpenAI API key from the .env file using python-dotenv at startup
2. IF the OpenAI API key is missing, THEN THE Agent SHALL not start and SHALL display an error message indicating the missing configuration
3. THE Agent SHALL load AWS credentials from environment variables or the standard AWS credential chain when CloudWatch_Tool is needed
4. THE Agent SHALL NOT expose API keys in logs, UI error messages, or chat responses
5. THE Agent SHALL NOT commit API keys to source control

### Requirement 18: LangGraph Agent Construction

**User Story:** As a developer, I want the agent built using LangGraph with proper state management, so that it follows modern agent architecture patterns.

#### Acceptance Criteria

1. THE Agent SHALL be implemented using LangGraph with a StateGraph defining the agent's execution flow
2. THE Agent SHALL use LangChain tool-calling with ChatOpenAI (gpt-4o, temperature 0) as the Agent_Brain
3. THE Agent SHALL define tools using the @tool decorator or BaseTool class with proper descriptions and schemas for LLM tool selection
4. THE Agent SHALL manage conversation state through LangGraph's state channels including messages, agent state, and working memory
5. THE Agent SHALL use LangChain's LCEL pipe operator for any sub-chains within tools (e.g., prompt | llm | parser for structured extraction)
6. THE Agent SHALL support configurable maximum reasoning iterations to prevent infinite loops

### Requirement 19: Scrubbing Profile Capabilities

**User Story:** As a user, I want the agent to know about different industry profiles and apply the right detection rules for my domain, so that domain-specific sensitive data is caught.

#### Acceptance Criteria

1. THE Agent SHALL support Scrub_Profiles: DEFAULT_PII, HEALTHCARE, FINANCIAL, PAYMENT_PCI, RETAIL, EDUCATION, HR_PAYROLL, LEGAL, GOVERNMENT, TELECOM, AUTOMOTIVE, and AI_SAAS
2. WHEN the user does not specify a profile, THE Agent SHALL apply DEFAULT_PII
3. WHEN the user mentions their domain context ("this is patient data", "these are financial records"), THE Agent SHALL suggest the appropriate profile and confirm before applying
4. THE Agent SHALL explain what each profile detects when the user asks ("what does the healthcare profile look for?")
5. THE Agent SHALL support applying multiple profiles simultaneously with conflict resolution using the more restrictive action
6. EVERY Industry_Profile SHALL inherit BASE_SECURITY plus DEFAULT_PII detection rules
7. THE DEFAULT_PII profile SHALL exempt values occupying recognized log-structural positions from DATE_TIME scrubbing, including a leading ISO timestamp and the keys `@timestamp`, `ts`, and `time`, while dates appearing in message bodies remain in scope
8. THE DEFAULT_PII profile SHALL resolve IP_ADDRESS handling from the active destination, permitting operational identifiers for INTERNAL_SIEM and applying a restrictive action for external destinations
9. WHEN the destination is unset and an operational-identifier decision depends on it, THE Agent SHALL ask the user rather than applying a destructive default
10. IF a Scrub_Profile is missing or fails schema validation, THEN THE Agent SHALL refuse to proceed and SHALL name the file that failed, and SHALL NOT fall back to built-in rules

### Requirement 20: Base Security Detection

**User Story:** As a security engineer, I want credentials always detected regardless of the selected industry profile, so that an incorrect profile does not result in secret leakage.

#### Acceptance Criteria

1. THE Base_Security_Profile SHALL detect: password, passcode, API key, access token, refresh token, OAuth token, JWT, authorization header, client secret, session cookie, private key, SSH private key, database credentials, cloud credential, and connection string containing credentials
2. THE Base_Security_Profile SHALL default detected credentials to REDACT or BLOCK according to configuration
3. AN Industry_Profile SHALL NOT reduce Base_Security protection without an explicitly controlled security exception
4. THE Agent SHALL always apply Base_Security_Profile rules before any other detection, regardless of user-specified profile

### Requirement 21: Healthcare Profile Capability

**User Story:** As a healthcare application user, I want the agent to detect medical information beyond ordinary PII when I tell it I'm working with health data.

#### Acceptance Criteria

1. WHEN the HEALTHCARE profile is active, THE Agent SHALL detect healthcare-specific categories including: medical record number, patient identifier, health plan beneficiary identifier, insurance member identifier, claim number, diagnosis, medical condition, symptoms, medical history, medication, prescription, medical procedure, surgery information, laboratory results, imaging results, mental-health information, genetic information, and patient-provider association
2. THE HEALTHCARE profile effective rules SHALL be: BASE_SECURITY + DEFAULT_PII + HEALTHCARE_SPECIFIC
3. THE Agent SHALL support configurable per-entity Scrub_Actions for healthcare entities

### Requirement 22: Financial Profile Capability

**User Story:** As a financial services user, I want the agent to detect financial identifiers and confidential data when I tell it I'm working with banking data.

#### Acceptance Criteria

1. WHEN the FINANCIAL profile is active, THE Agent SHALL additionally detect: bank account number, routing number, IBAN, SWIFT/BIC, loan number, mortgage identifier, brokerage account, investment account, retirement account, credit score, tax identifier, customer financial account identifier, wire instructions, and financial-account credentials
2. THE FINANCIAL profile effective rules SHALL be: BASE_SECURITY + DEFAULT_PII + FINANCIAL_SPECIFIC
3. THE Agent SHALL support configurable per-entity Scrub_Actions for financial entities

### Requirement 23: Payment Card / PCI Profile Capability

**User Story:** As a payment application user, I want the agent to detect and strictly handle payment card data when working with transaction logs.

#### Acceptance Criteria

1. WHEN the PAYMENT_PCI profile is active, THE Agent SHALL additionally detect: PAN, CVV/CVC, PIN, card expiration, track data, card authentication information, and cardholder name
2. THE default actions for CVV, PIN, and TRACK_DATA SHALL be REDACT or BLOCK
3. THE default action for PAN SHALL be MASK or TOKENIZE
4. THE Agent SHALL NOT store CVV or PIN values as reversible tokens

### Requirement 24: AI / SaaS Profile Capability

**User Story:** As an AI platform user, I want the agent to detect platform credentials and customer content leakage in AI pipeline logs.

#### Acceptance Criteria

1. WHEN the AI_SAAS profile is active, THE Agent SHALL additionally inspect for: API credentials, model/provider tokens, database credentials, connection strings, internal authentication information, user prompts, system-prompt content designated confidential, agent memory, tool arguments, tool responses, retrieved customer documents, proprietary source code, and proprietary customer content
2. THE AI_SAAS profile SHALL apply Base_Security protection regardless of other configuration

### Requirement 25: Profile Configuration as Data

**User Story:** As a developer, I want profiles maintained as structured configuration rather than hard-coded logic, so that profiles are reviewable, testable, and auditable.

#### Acceptance Criteria

1. THE profile definitions SHALL be maintained in structured YAML configuration files
2. THE profile configurations SHALL be version-controlled, reviewable, and testable
3. THE Agent SHALL support custom profiles that inherit from existing profiles and add organization-specific entity detection
4. EVERY Scrub_Profile SHALL have a version identifier
5. THE Agent SHALL support adding new profiles without modifying core agent logic

### Requirement 26: Normalized Event Model

**User Story:** As a developer, I want all source tools to output a common representation, so that the detection tools operate uniformly regardless of data origin.

#### Acceptance Criteria

1. EACH source tool SHALL produce a Normalized_Event containing: source_type, timestamp, source_metadata, content, and raw_content
2. Source-specific metadata SHALL remain separate from detection-target content
3. THE detection tools SHALL operate against the Normalized_Event content rather than invoking source-specific parsing
4. Adding a new source tool SHALL NOT require modification to detection tool logic

### Requirement 27: Large File and Streaming Processing

**User Story:** As a user, I want the agent to handle large log files without running out of memory, so that production-scale data can be scanned.

#### Acceptance Criteria

1. THE File_Reader_Tool SHALL support buffered streaming for large files without loading the entire file into memory
2. THE Agent SHALL support configurable file-size limitations
3. THE streaming process SHALL preserve ordering of output
4. THE sanitized output SHALL maintain the original structure where technically possible
5. IF a processing failure occurs, THEN THE Agent SHALL report the failure without including raw sensitive content in the error message
6. THE Agent SHALL report progress during large file processing ("Processed 50% of file, found 23 entities so far...")

### Requirement 28: Entity Reconciliation

**User Story:** As a user, I want detection results from multiple tools combined without duplicates, so that I get a clean consolidated view of all detected PII.

#### Acceptance Criteria

1. THE Agent SHALL reconcile detections from Presidio_Tool, SpaCy_Tool, and any contextual detection before presenting results
2. THE Agent SHALL convert all chunk-local entity offsets into whole-document coordinates before reconciliation, and no chunk-local offset SHALL reach the Anonymizer_Tool
3. THE reconciliation logic SHALL identify overlapping entities by global document position
4. THE reconciliation logic SHALL normalize equivalent entity names across tools
5. THE reconciliation logic SHALL deduplicate entities detected within a chunk-overlap region by global span
6. WHEN overlapping entities conflict, THE reconciliation logic SHALL resolve them using this total precedence order: (a) longest span wins; (b) higher severity wins; (c) validator-backed detection wins; (d) detector precedence custom-security > Presidio > spaCy; (e) lexicographically smaller type name
7. THE reconciliation logic SHALL produce byte-identical output for identical input across repeated runs
8. THE reconciliation logic SHALL retain confidence and source metadata
9. THE reconciliation logic SHALL record whether a confidence value is calibrated or heuristic, and SHALL NOT weight a heuristic constant as though it were a calibrated probability
10. EACH final entity SHALL include: type, start, end, confidence, confidence_source, severity, and detected_by (list of detection sources)

### Requirement 29: Result Presentation and Export

**User Story:** As a user, I want the agent to present findings clearly in chat and offer export options, so that I can use the results in my workflow.

#### Acceptance Criteria

1. WHEN detection completes, THE Agent SHALL present a summary including: total entity count, breakdown by type, and severity assessment
2. THE Agent SHALL display detected entities with their type, extracted text (or masked preview), confidence score, and detection source
3. THE Agent SHALL offer to export results in multiple formats: scrubbed text file, JSON detection report, or inline in chat
4. THE Agent SHALL use color-coded or categorized indicators for entity severity (high: credentials/secrets, medium: direct PII, low: indirect identifiers)
5. THE Agent SHALL offer follow-up actions: "Would you like me to redact these and provide a clean version?"

### Requirement 30: Confidence Threshold Configuration

**User Story:** As a user, I want to tell the agent how sensitive my detection should be, so that I can balance between catching all potential PII and reducing false positives.

#### Acceptance Criteria

1. THE Agent SHALL accept confidence threshold instructions via natural language ("be more strict", "only show high confidence matches", "use threshold 0.7")
2. THE Agent SHALL default the Confidence_Threshold to 0.4 when not specified
3. THE Agent SHALL explain the trade-off when the user asks about sensitivity ("Higher threshold means fewer false positives but may miss some real PII")
4. THE Session_Memory SHALL remember the user's preferred threshold within the session

### Requirement 31: Safe LLM Tool Usage

**User Story:** As a security engineer, I want the agent to be cautious about what content it processes through external LLM calls, so that sensitive data is not inadvertently sent to AI services beyond what the reasoning loop requires.

#### Acceptance Criteria

1. THE Agent SHALL NOT place raw source content into the Agent_Brain reasoning context under any circumstance — source content SHALL remain server-side and be referenced only by an opaque Content_Handle
2. THE Agent SHALL NOT transmit entity character offsets, entity text values for HIGH severity entities, or any detected secret value to the Agent_Brain
3. THE Agent_Brain SHALL receive only: entity types, entity counts, severity classifications, coverage metadata, refusal reasons, and Content_Handles
4. WHEN an excerpt of scanned content must be shown at explicit user request, THE Agent SHALL wrap it in an untrusted-data envelope bearing a per-session random identifier and SHALL escape role-marker sequences within it
5. THE Agent SHALL support a configuration flag restricting the maximum metadata size sent to the Agent_Brain per reasoning step
6. THE Agent SHALL log LLM usage metadata (token count, request count) without logging raw sensitive content
7. THE Agent SHALL NOT forward API keys, passwords, private keys, or session credentials to the Agent_Brain for the purpose of determining whether they are secrets

### Requirement 32: Tokenization Capability

**User Story:** As a user, I want the agent to support reversible tokenization when I need to recover original values later.

#### Acceptance Criteria

1. THE Anonymizer_Tool SHALL support TOKENIZE as a Scrub_Action
2. WHEN tokenization is applied, THE Anonymizer_Tool SHALL replace the original value with a surrogate identifier that does not expose the underlying information
3. THE Token_Vault SHALL require explicit authorization for detokenization
4. Detokenization SHALL NOT be an Agent capability — it SHALL NOT be registered in the Tool_Registry and no path SHALL exist from the Reasoning_Loop to it
5. THE Agent MAY state that a value is tokenized but SHALL NOT be able to resolve a surrogate to its original value
6. Detokenization SHALL be performed only as an out-of-band operator action, and every access SHALL be audited
7. THE Agent SHALL NOT use reversible tokenization for data categories explicitly prohibited from storage (CVV, PIN)
8. THE Token_Vault SHALL use cryptographically secure random generation to prevent token prediction
9. THE Token_Vault SHALL verify surrogate uniqueness so that two different source values never produce the same token
10. THE Token_Vault SHALL be scoped to a single session and SHALL NOT resolve tokens issued in another session
11. THE HASH Scrub_Action SHALL be documented as pseudonymization rather than anonymization, and SHALL NOT be permitted as the configured action for low-entropy high-severity entity types including US_SSN, CREDIT_CARD, CVV, and PIN

### Requirement 33: Adversarial Evasion Resistance

**User Story:** As a security engineer, I want the detection tools resilient to deliberate obfuscation, so that adversaries cannot bypass PII detection through encoding or character manipulation.

#### Acceptance Criteria

1. THE Presidio_Tool SHALL normalize Unicode homoglyphs before detection
2. THE Presidio_Tool SHALL detect and handle zero-width characters and invisible Unicode injections that may split recognizable patterns
3. THE Agent SHALL support detection of Base64-encoded sensitive values within log content where technically feasible
4. THE Agent SHALL support detection of hex-encoded sensitive values within structured log fields where technically feasible
5. THE detection pipeline SHALL apply normalization before pattern matching to counter simple obfuscation (whitespace insertion, case alternation)
6. WHEN adversarial evasion patterns are detected, THE Agent SHALL flag the content for elevated inspection and inform the user

### Requirement 34: Rate Limiting and Cost Controls

**User Story:** As a platform operator, I want the agent's resource usage controlled, so that it cannot be overwhelmed by excessive requests or run up unbounded LLM costs.

#### Acceptance Criteria

1. THE Agent SHALL support configurable maximum file size limits for file-based processing
2. THE Agent SHALL support configurable maximum text length limits for text-based processing
3. THE Agent SHALL support configurable limits on reasoning loop iterations per request
4. THE Agent SHALL support configurable LLM token budget per session
5. IF a limit is exceeded, THEN THE Agent SHALL inform the user conversationally and suggest alternatives (e.g., "This file is very large. Want me to scan just the first 10,000 lines?")

### Requirement 35: Data Protection During Processing

**User Story:** As a security engineer, I want sensitive data protected during the agent's processing, so that the agent itself does not become a data leakage vector.

#### Acceptance Criteria

1. WHEN the Agent communicates with external services (AWS APIs, LLM providers), THE Agent SHALL use TLS 1.2 or higher
2. WHEN temporary files are created during processing, THE Agent SHALL store them in a restricted-access temporary directory
3. WHEN processing completes or fails, THE Agent SHALL securely delete all temporary processing artifacts
4. THE Agent SHALL NOT write unsanitized content to debug logs during processing
5. THE Agent SHALL NOT include raw sensitive content in chat history that persists beyond the session

### Requirement 36: Observability and Health

**User Story:** As a developer, I want visibility into the agent's operational health, so that degraded capabilities are identified quickly.

#### Acceptance Criteria

1. THE Agent SHALL expose a health status indicating readiness of: Presidio engine, spaCy model, LLM connectivity, and configured source tools
2. IF the spaCy model fails to load, THEN THE Agent SHALL report degraded detection capability to the user and SHALL NOT silently process text with reduced coverage
3. THE Agent SHALL maintain a Coverage_Ledger for every scan recording: bytes processed, bytes total, detectors executed, detectors failed, and whether every detector required by the active profile succeeded
4. IF a Presidio recognizer fails during processing, THEN THE Agent SHALL record the failure in the Coverage_Ledger, continue detection with remaining recognizers for REPORTING purposes only, and label the results UNVERIFIED
5. WHEN the Coverage_Ledger reports incomplete coverage, THE Agent SHALL refuse to produce or export a sanitized artifact and SHALL state the refusal reason in plain language
6. EACH Scrub_Profile SHALL declare its required detectors, and THE Agent SHALL treat a profile whose required detector is unavailable as unavailable rather than silently reduced in scope
7. THE Agent SHALL log structured processing events (JSON format) for debugging without including sensitive content

### Requirement 37: MVP Scope Definition

**User Story:** As a product owner, I want a clear MVP boundary so that the first implementation delivers a working agent with core capabilities.

#### Acceptance Criteria

1. THE first implementation SHALL deliver a conversational agent with the ReAct reasoning loop via LangGraph
2. THE first implementation SHALL include tools: Presidio_Tool, SpaCy_Tool, File_Reader_Tool, CloudWatch_Tool, EventLog_Tool, Anonymizer_Tool, and Profile_Resolver_Tool
3. THE first implementation SHALL support profiles: BASE_SECURITY, DEFAULT_PII, HEALTHCARE, FINANCIAL, PAYMENT_PCI, and AI_SAAS
4. THE first implementation SHALL support Scrub_Actions: REPLACE, MASK, HASH, TOKENIZE, and REDACT
5. THE first implementation SHALL provide the Streamlit Chat_Interface with state indicators and streaming responses
6. THE first implementation SHALL include Session_Memory for within-session context
7. Phase 2 SHALL include: additional source tools (Linux logs, Kubernetes), remaining industry profiles (Education, HR, Retail, Telecom, Legal, Government, Automotive), batch processing, REST API, and scheduled jobs

### Requirement 38: International PII and Locale Support

**User Story:** As a user working with international data, I want PII detection to extend beyond US-centric patterns.

#### Acceptance Criteria

1. THE Presidio_Tool SHALL support configurable locale/language for detection beyond English
2. THE architecture SHALL support adding locale-specific recognizers (EU national IDs, UK NHS numbers, Canadian SIN, Australian TFN)
3. WHEN the user specifies a locale context ("this is UK data", "scan for German identifiers"), THE Agent SHALL apply locale-appropriate recognizers
4. THE Agent SHALL NOT assume US formatting for phone numbers, addresses, or identification numbers when a non-US locale is indicated

### Requirement 39: False Positive Management

**User Story:** As a user, I want to tell the agent that a detection is a false positive, so that it learns within the session and stops flagging known-safe values.

#### Acceptance Criteria

1. THE Agent SHALL accept user feedback on detections: "that's not PII", "ignore that one", "the IP 10.0.0.1 is safe"
2. THE Agent SHALL maintain a session-scoped allowlist of user-confirmed safe values
3. WHEN an allowlisted value is encountered in subsequent scans, THE Agent SHALL exclude it from detection results
4. THE Agent SHALL confirm allowlist additions: "Got it, I'll ignore 10.0.0.1 for the rest of this session"
5. THE allowlist SHALL be scoped to the current session and profile to prevent unsafe cross-context exclusions

### Requirement 40: Destination-Aware Policy

**User Story:** As a security architect, I want the agent to consider where sanitized data is going when deciding how aggressively to scrub.

#### Acceptance Criteria

1. THE Agent SHALL support destination context (INTERNAL_SIEM, EXTERNAL_ANALYTICS, EXTERNAL_LLM, FILE, S3) when resolving Scrub_Actions
2. WHEN destination is INTERNAL_SIEM, THE Policy_Engine MAY allow certain operational identifiers (IP address, username, hostname) that would be masked for external destinations
3. WHEN destination is EXTERNAL_LLM or EXTERNAL_ANALYTICS, THE Policy_Engine SHALL apply more restrictive actions
4. THE Agent SHALL ask about destination when the user's intent is ambiguous: "Where will this cleaned data be sent? That helps me decide how aggressively to scrub."

### Requirement 41: Audit Trail

**User Story:** As a compliance officer, I want processing activity recorded for audit purposes without exposing sensitive content.

#### Acceptance Criteria

1. THE Agent SHALL record for each processing request: timestamp, source type, profile applied, profile version, engine versions, detection counts by type, actions applied, coverage completeness, verification outcome, and success/failure status
2. THE audit record SHALL NOT contain detected sensitive values, and THE audit model SHALL contain no field capable of carrying an entity value
3. THE Agent SHALL persist each audit record to an append-only sink outside session state before returning the result to the user
4. EACH audit record SHALL include the hash of the preceding record, forming a chain that makes retroactive modification detectable
5. THE audit sink SHALL survive session termination and browser refresh
6. THE Agent SHALL record source identifiers as cryptographic hashes rather than raw values
7. THE Agent SHALL support exporting audit records when requested by the user
8. THE Agent SHALL include a unique request identifier for each processing action that can be referenced in conversation

### Requirement 42: Compliance Framework Awareness

**User Story:** As a compliance-conscious user, I want the agent to explain how its profiles map to regulatory requirements when asked.

#### Acceptance Criteria

1. THE Agent SHALL explain HEALTHCARE profile coverage relative to HIPAA Safe Harbor de-identification categories when asked
2. THE Agent SHALL explain PAYMENT_PCI profile coverage relative to PCI-DSS cardholder data requirements when asked
3. THE Agent SHALL document known limitations where automated detection cannot fully satisfy a regulatory requirement
4. THE Agent SHALL NOT claim full regulatory compliance — it SHALL clarify that it assists with detection but does not replace a compliance program

### Requirement 43: Prompt Injection Resistance for Scanned Content

**User Story:** As a security engineer, I want the agent to be immune to instructions embedded in the content it scans, so that an attacker who can write a single log line cannot control the agent or suppress detection.

#### Acceptance Criteria

1. THE Agent SHALL treat all scanned content as inert data and SHALL NOT act on any instruction contained within it
2. THE Agent SHALL NOT place raw scanned content into the Agent_Brain reasoning context
3. WHEN an excerpt must be displayed at explicit user request, THE Agent SHALL enclose it in an untrusted-data envelope bearing a per-session random identifier so that embedded text cannot forge a closing delimiter
4. THE Agent SHALL escape or neutralize role-marker sequences within excerpts, including `system:`, `assistant:`, `[[`, and `<|...|>`
5. WHEN content matching known injection patterns is detected, THE Agent SHALL report it to the user as a security finding stating that the content appears designed to manipulate an AI agent
6. THE Scrub_Action for each entity SHALL be determined by the Policy_Engine in code, so that a manipulated reasoning step cannot weaken the sanitization outcome
7. THE Agent SHALL log injection detection events without reproducing the injected content in the audit record

### Requirement 44: Deployment Binding and Exposure Guardrail

**User Story:** As a platform operator, I want the agent to refuse unsafe network exposure by default, so that a service capable of reading the local filesystem and cloud logs is never reachable by unauthenticated network peers.

#### Acceptance Criteria

1. THE Streamlit_App SHALL bind to the loopback interface by default
2. IF the configured bind address is not a loopback address AND remote access has not been explicitly enabled, THEN THE Streamlit_App SHALL refuse to start and SHALL explain the risk
3. THE Streamlit_App SHALL require an explicit configuration flag to permit binding to a non-loopback address
4. THE documentation SHALL state that non-loopback deployment requires an authenticating reverse proxy
5. THE Streamlit_App SHALL validate at startup that required secrets are present and that pinned engine versions match the installed versions
6. THE Streamlit_App SHALL sweep and remove orphaned temporary directories from prior runs at startup

### Requirement 45: Policy Enforcement Point

**User Story:** As a security architect, I want a single component to own every scrub-action decision, so that no other component — including the reasoning loop — can weaken a policy outcome.

#### Acceptance Criteria

1. THE Policy_Engine SHALL be the only component that determines the Scrub_Action applied to a detected entity
2. THE Policy_Engine SHALL resolve each entity's action as the most restrictive of the profile-mandated action and any requested action
3. WHEN a requested action is less restrictive than the profile-mandated action, THE Policy_Engine SHALL discard the request and apply the profile-mandated action
4. WHEN the entity originates from the Base_Security_Profile, THE Policy_Engine SHALL ignore any requested action entirely
5. THE Policy_Engine SHALL record for each entity: the profile-mandated action, the requested action, the applied action, and the deciding rule
6. THE Agent_Brain SHALL be able to request a more restrictive action but SHALL be structurally incapable of requesting a less restrictive one
7. FOR every entity, the applied action SHALL satisfy `ACTION_PRIORITY[applied] >= ACTION_PRIORITY[profile_mandated]`

### Requirement 46: Deterministic Scrub Pipeline

**User Story:** As a developer, I want the detect-to-scrub sequence implemented as deterministic code rather than orchestrated by the reasoning loop, so that entity positions and coverage are never subject to model error.

#### Acceptance Criteria

1. THE detection, reconciliation, policy resolution, application, and verification stages SHALL execute as a single deterministic pipeline invoked by one coarse-grained tool
2. THE Agent_Brain SHALL select the source and the profile but SHALL NOT carry content, entity positions, or intermediate results between pipeline stages
3. THE pipeline SHALL iterate all chunks of a source under deterministic control and SHALL NOT delegate coverage decisions to the Agent_Brain
4. THE pipeline SHALL return only after the Coverage_Ledger shows complete coverage or an explicitly user-approved truncation
5. THE pipeline SHALL produce identical output for identical input, profile, and engine versions
6. EACH pipeline stage SHALL be independently unit testable without an LLM present
7. THE pipeline SHALL record the engine versions and profile version used, so that a result can be reproduced later
