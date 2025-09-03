from flask import Flask, request, jsonify, render_template, send_file
from markdown_it import MarkdownIt
from Agent.agent import model
from Agent import tools
from Agent.api_keys import GROQ_API_KEY
from pathlib import Path
from groq import Groq
import os
import uuid
import re

app = Flask(__name__)
md = MarkdownIt()

client = Groq(api_key=GROQ_API_KEY)

# In-memory storage for chat sessions and history
chat_sessions = {}
chat_history = {}

def generate_chat_title(user_input):
    """
    Generate a concise, descriptive chat title using AI analysis.
    """
    # Clean and truncate the input to prevent issues
    cleaned_input = user_input.strip()
    
    # If input is too long, take first sentence or first 300 characters
    if len(cleaned_input) > 300:
        # Try to get first sentence
        sentences = cleaned_input.split('. ')
        if sentences and len(sentences[0]) <= 300:
            cleaned_input = sentences[0]
        else:
            # Fallback to first 300 characters
            cleaned_input = cleaned_input[:300]
    
    try:
        print(f"🔄 Generating title for input: '{cleaned_input[:50]}...'")
        
        completion = client.chat.completions.create(
            model="openai/gpt-oss-20b",
            messages=[
                {
                    "role": "system",
                    "content": """You are a chat title generator. Create a concise, descriptive title (3-6 words) that captures the main topic or request in the user's message.

Rules:
- Use 3-6 words maximum
- Be specific and descriptive
- Use title case (capitalize main words)
- For code requests, include the technology/language
- For questions, focus on the topic being asked about
- For tasks, focus on what needs to be done
- Don't use quotes or extra punctuation
- Make it searchable and memorable

Examples:
- "How to center a div in CSS" → "CSS Div Centering Help"
- "Write a Python function for sorting" → "Python Sorting Function Code"
- "What is machine learning?" → "Machine Learning Explanation"
- "Help me debug this error" → "Code Debugging Assistance"
- "Create a REST API" → "REST API Development"
"""
                },
                {
                    "role": "user",
                    "content": cleaned_input
                }
            ],
            temperature=0.3,  # Lower temperature for more consistent results
            max_tokens=300,
            stream=False,
        )
        
        title = completion.choices[0].message.content.strip()
        
        # Clean up the title (remove quotes, extra punctuation)
        title = re.sub(r'^["\']|["\']$', '', title)  # Remove surrounding quotes
        title = re.sub(r'[.!?]+$', '', title)  # Remove trailing punctuation
        title = title.strip()
        
        print(f"🤖 Generated title: '{title}'")
        
        if not title:
            raise Exception("Empty response from model")
            
        return title
        
    except Exception as e:
        print(f"❌ Title generation failed: {e}")
        
        # Improved fallback logic
        words = cleaned_input.split()
        
        # For code-related content
        code_keywords = ['code', 'function', 'class', 'method', 'script', 'program', 'debug', 'error', 'api', 'database', 'sql', 'python', 'javascript', 'java', 'c++', 'html', 'css', 'react', 'vue', 'angular']
        if any(keyword in cleaned_input.lower() for keyword in code_keywords):
            # Try to identify the technology
            tech_words = []
            for word in words[:10]:  # Check first 10 words
                word_lower = word.lower().strip('.,!?()[]{}')
                if word_lower in ['python', 'javascript', 'java', 'c++', 'html', 'css', 'react', 'vue', 'angular', 'node', 'php', 'ruby', 'go', 'rust', 'sql', 'mongodb']:
                    tech_words.append(word.title())
            
            if tech_words:
                fallback_title = f"{tech_words[0]} Code Help"
            else:
                fallback_title = "Programming Code Help"
        else:
            # For general questions/requests
            # Filter out common words and take meaningful ones
            stop_words = ['the', 'and', 'can', 'you', 'help', 'with', 'how', 'what', 'where', 'when', 'why', 'i', 'me', 'my', 'a', 'an', 'to', 'for', 'of', 'in', 'on', 'at', 'by']
            meaningful_words = []
            
            for word in words[:15]:  # Check first 15 words
                clean_word = re.sub(r'[^\w]', '', word).lower()
                if len(clean_word) > 2 and clean_word not in stop_words:
                    meaningful_words.append(word.title())
                    if len(meaningful_words) >= 4:
                        break
            
            if meaningful_words:
                fallback_title = ' '.join(meaningful_words[:4])
            else:
                # Final fallback - just use first few words
                fallback_title = ' '.join(words[:4])
                fallback_title = ' '.join(word.title() for word in fallback_title.split())
        
        # Ensure title isn't too long
        if len(fallback_title) > 50:
            fallback_title = fallback_title[:50].rsplit(' ', 1)[0]
        
        print(f"🔄 Using fallback title: '{fallback_title}'")
        return fallback_title

def get_or_create_session(session_id, user_input):
    if session_id and session_id in chat_sessions:
        return chat_sessions[session_id], session_id
    
    new_session_id = str(uuid.uuid4())
    chat_sessions[new_session_id] = model.start_chat(history=[])

    # Generate chat title using the improved title generation
    summary = generate_chat_title(user_input)

    chat_history[new_session_id] = {'summary': summary, 'messages': []}
    print(f"📝 Created session '{new_session_id}' with title: '{summary}'")
    
    return chat_sessions[new_session_id], new_session_id

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    user_input = data.get('message')
    session_id = data.get('session_id')

    if not user_input:
        return jsonify({'error': 'No message provided'}), 400

    chat_session, new_session_id = get_or_create_session(session_id, user_input)
    if not session_id:
        session_id = new_session_id

    response = chat_session.send_message(user_input)
    
    # Save history
    chat_history[session_id]['messages'].append({'role': 'user', 'text': user_input, 'labels': []})
    
    try:
        # Handle function calls
        while True:
            # Check if the response contains function calls
            if not response.candidates or not response.candidates[0].content.parts:
                return jsonify({'response': "AI: I didn't receive a proper response."})
                
            function_calls_made = False
            
            for part in response.candidates[0].content.parts:
                # Check if this part is a function call
                if hasattr(part, 'function_call') and part.function_call:
                    function_calls_made = True
                    function_call = part.function_call
                    
                    print(f"Executing: {function_call.name}")
                    
                    # Execute the function call
                    if function_call.name == 'web_search':
                        tool_result = tools.web_search(function_call.args['query'])
                    elif function_call.name == 'create_calendar_event':
                        tool_result = tools.create_calendar_event(**function_call.args)
                    elif function_call.name == 'search_calendar_events':
                        tool_result = tools.search_calendar_events(**function_call.args)
                    elif function_call.name == 'update_calendar_event':
                        tool_result = tools.update_calendar_event(**function_call.args)
                    elif function_call.name == 'delete_calendar_event':
                        tool_result = tools.delete_calendar_event(**function_call.args)
                    elif function_call.name == 'send_email':
                        tool_result = tools.send_email(**function_call.args)
                    elif function_call.name == 'read_emails':
                        tool_result = tools.read_emails(**function_call.args)
                    elif function_call.name == 'add_label':
                        tool_result = tools.add_label(**function_call.args)
                    else:
                        tool_result = {"error": f"Unknown function: {function_call.name}"}
                    
                    # Create function response using the newer approach
                    function_response_part = {
                        "function_response": {
                            "name": function_call.name,
                            "response": tool_result
                        }
                    }
                    
                    # Send the tool result back to the model
                    response = chat_session.send_message(function_response_part)
                    break
            
            # If no function calls were made, extract text response
            if not function_calls_made:
                text_parts = []
                for part in response.candidates[0].content.parts:
                    if hasattr(part, 'text') and part.text:
                        text_parts.append(part.text)
                
                if text_parts:
                    bot_response = ''.join(text_parts)
                    chat_history[session_id]['messages'].append({'role': 'bot', 'text': bot_response, 'labels': []})
                    html_response = md.render(bot_response)
                    return jsonify({'response': html_response, 'session_id': session_id})
                else:
                    return jsonify({'response': "AI: I received a response but couldn't extract the text.", 'session_id': session_id})

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'response': "AI: I encountered an issue and couldn't retrieve a response.", 'session_id': session_id})

# New endpoint to rename existing chats
@app.route('/rename_chat', methods=['POST'])
def rename_chat():
    """
    Endpoint to rename an existing chat using the improved title generation.
    """
    data = request.json
    session_id = data.get('session_id')
    
    if not session_id or session_id not in chat_history:
        return jsonify({'error': 'Invalid session ID'}), 400
    
    # Get the first user message to generate a new title
    messages = chat_history[session_id]['messages']
    first_user_message = next((msg['text'] for msg in messages if msg['role'] == 'user'), '')
    
    if not first_user_message:
        return jsonify({'error': 'No user messages found'}), 400
    
    # Generate new title
    new_title = generate_chat_title(first_user_message)
    chat_history[session_id]['summary'] = new_title
    
    print(f"🔄 Renamed chat '{session_id}' to: '{new_title}'")
    
    return jsonify({
        'session_id': session_id,
        'new_title': new_title
    })

@app.route('/history', methods=['GET'])
def get_history():
    return jsonify([{'id': sid, 'summary': info['summary']} for sid, info in chat_history.items()])

@app.route('/history/<session_id>', methods=['GET'])
def get_session_history(session_id):
    session_info = chat_history.get(session_id)
    if not session_info:
        return jsonify([])
    history = session_info.get('messages', [])
    return jsonify([{'role': item['role'], 'text': md.render(item['text']), 'labels': item.get('labels', [])} for item in history])

@app.route('/speech', methods=['POST'])
def speech():
    data = request.json
    text = data.get('text')
    if not text:
        return jsonify({'error': 'No text provided'}), 400

    try:
        speech_file_path = Path(__file__).parent / "speech.wav"
        response = client.audio.speech.create(
            model="playai-tts",
            voice="Mitch-PlayAI",
            response_format="wav",
            input=text,
        )
        # The response object is a file-like object. Read its content and write to a file.
        with open(speech_file_path, "wb") as f:
            f.write(response.read())
        return send_file(speech_file_path, mimetype="audio/wav")
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/transcribe', methods=['POST'])
def transcribe_audio():
    if 'audio_data' not in request.files:
        return jsonify({'error': 'No audio file provided'}), 400

    audio_file = request.files['audio_data']
    filename = "audio.webm"
    audio_file.save(filename)

    try:
        with open(filename, "rb") as file:
            transcription = client.audio.transcriptions.create(
              file=(filename, file.read()),
              model="whisper-large-v3-turbo",
              response_format="verbose_json",
            )
        os.remove(filename)
        return jsonify({'text': transcription.text})
    except Exception as e:
        if os.path.exists(filename):
            os.remove(filename)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)