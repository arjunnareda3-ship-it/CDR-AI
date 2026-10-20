===============================================
   SHADOW CDR - Full Telecom CDR Analyzer
   BCA Cyber Security Project
   Student: Arjun Singh
===============================================

HOW TO OPEN (VS Code / Local)
-----------------------------
1. Extract this folder
2. Open folder in VS Code
3. Open login.html in browser (Live Server recommended)
   OR just double-click login.html

The login screen starts with an animated "WELCOME TO CDR" intro.
Choose SKIP INTRO or press Escape to continue immediately.

Login: arjun / 1234 (admin)

ROLES AND ACCESS
----------------
- Admin can create USER or OWNER accounts, delete accounts, and add/delete CDR records.
- OWNER can view CDR reports, use AI, and grant/revoke AI access for USER accounts.
- ADMIN can also grant/revoke AI access for USER accounts.
- USER can view the website and reports but cannot change CDR data. AI is locked until an ADMIN or OWNER grants access.
- Roles and approvals in this static demo are stored in the browser's localStorage. They are not secure
  against someone with browser/devtools access; production-grade enforcement requires server-side
  authentication and authorization.


FULL CDR FIELDS INCLUDED
------------------------
Target / A Party Number
Call Type (In/Out)
Type of Connection
B Party Number
LRN Called No
SIM Operator
LRN Operator Name with LSA
Call Date / Call Time / Call Duration
First BTS Location-Address / First Cell ID
Last BTS Location-Address / Last Cell ID
SMS Center Number
Service Type (Voice/SMS)
IMEI / IMSI
Call Forwarding Number
Roaming Circle Name
Switch ID / MSC ID
In TG / Out TG


SAMPLE DATA
-----------
- Sample Data mode contains 429 generated fictional records across 12 cities and 4 SIM operators.
- Sample phone numbers, IMEI, and IMSI values are intentionally non-routable demo values, not subscriber data.
- An already-populated Firebase collection continues to show its existing records; the sample set is used in Sample Data mode or to seed an empty collection.


FEATURES
--------
- Login + Admin Panel (create users)
- Full CDR Add / Delete
- Suspicious detection (Night / Short / Long calls)
- Charts + Analysis
- Export full CSV report and print/save a CDR report as PDF
- Generate an AI-assisted findings report for PDF export
- AI chat with browser speech input, spoken replies, chat export, and clear/stop controls
- Local Ollama AI support; CDR context stays on this computer in Ollama mode
- Firebase database support

AI CHAT AND VOICE
-----------------
Use SPEAK to dictate a question (browser microphone permission required).
Replies are read aloud by default; change the voice language, disable Read replies,
read the latest reply again, stop audio, export the chat as text, or clear the chat.
Speech recognition and speech playback depend on browser support; use a current
Chrome or Edge browser and HTTPS/localhost for microphone access.
If SPEAK does not start, allow Microphone for the deployed site in the browser's
address-bar site settings, reload, and try again. Check Windows microphone privacy
settings and make sure the browser can reach its speech-recognition service.
For clear Hindi spoken replies, install a Hindi (India) text-to-speech voice in
Windows Speech settings and reload the website. The app selects an installed
voice matching the chosen language when available and speaks at a slightly slower pace.
Chat follow-up questions can use the three most recent successful question-and-answer
pairs; choose CLEAR CHAT to start a fresh conversation.
Use only records you are authorized to process. CDR summary context is sent only
to the local Ollama service configured on this computer.

LOCAL AI (OLLAMA - DEFAULT)
--------------------------
1. Install Ollama for Windows from https://ollama.com/download.
2. In PowerShell, download a model: ollama pull llama3.2
   (You can use another installed Ollama model by changing the model field in AI chat.)
   A larger multilingual model may give stronger answers if your computer has enough memory.
   Smaller models usually respond faster; the first reply can take longer while Ollama loads a model.
   The app keeps the model loaded for up to 10 minutes after a request to speed up follow-up replies.
3. Open this project with VS Code Live Server at http://localhost:5500.
   Do not use file:// for Ollama; browsers block local API requests from that origin.
4. Ollama must allow the Live Server origin. In PowerShell, run:
   setx OLLAMA_ORIGINS "http://localhost:5500,http://127.0.0.1:5500"
   Then quit Ollama from the Windows system tray and start it again.
   If Live Server uses another port, add that exact origin to OLLAMA_ORIGINS.
5. In the app's AI Assistant, leave LOCAL OLLAMA selected, confirm the address
   (http://localhost:11434) and model (llama3.2), then choose TEST LOCAL.
   The model field suggests models already installed in Ollama. If your chosen
   model is missing, run the displayed `ollama pull <model>` command in PowerShell.
   Chat questions and AI ANALYSIS REPORT will use the model on this computer.

The app validates that the Ollama URL is loopback-only to avoid sending CDR
context to a remote host. The separate Firebase database may still sync records
to Firebase when configured.

PDF AND REPORTS
---------------
In CDR RECORDS, select AI ANALYSIS REPORT to generate findings from the records.
Then choose SAVE PDF / PRINT and select Save as PDF in the browser print dialog.
EXPORT CSV remains available separately.

VERCEL DEPLOYMENT
-----------------
1. Deploy this project folder to Vercel.
2. The AI assistant still requires Ollama running on the same computer as the browser.
   A hosted website cannot reach a visitor's local Ollama unless its origin is
   explicitly allowed by Ollama's CORS settings.


FIREBASE
--------
Config already set for project: shadowcdr-d3a9a
Make sure Firestore Rules allow read/write (test mode).


Vercel Deploy: Upload this folder as-is.
===============================================
