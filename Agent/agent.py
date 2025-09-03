import google.generativeai as genai
from .api_keys import GENAI_API_KEY
from .system_prompt import get_system_prompt
from . import tools

# Configure APIs
genai.configure(api_key=GENAI_API_KEY)

# Set up the model with tools
system_prompt = get_system_prompt()

model = genai.GenerativeModel(
    model_name='gemini-2.5-flash',
    tools=[tools.web_search, tools.create_calendar_event, tools.search_calendar_events, tools.update_calendar_event, tools.delete_calendar_event, tools.send_email, tools.read_emails],
    system_instruction=system_prompt
)

def run_conversation(chat_session, user_input: str):
    """Simulates a conversation with the AI personal assistant."""
    response = chat_session.send_message(user_input)
    
    try:
        # Handle function calls
        while True:
            # Check if the response contains function calls
            if not response.candidates or not response.candidates[0].content.parts:
                print("AI: I didn't receive a proper response.")
                break
                
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
                    print(f"AI: {''.join(text_parts)}")
                else:
                    print("AI: I received a response but couldn't extract the text.")
                break

    except Exception as e:
        print(f"An error occurred: {e}")
        print("AI: I encountered an issue and couldn't retrieve a response.")

def main():
    """Main function to run the AI agent."""
    # Initialize chat session outside the loop to maintain memory
    chat_session = model.start_chat(history=[])

    while True:
        user_input = input("You: ").strip()
        
        # Handle empty input
        if not user_input:
            print("AI: Please type something for me to help you with!")
            continue
            
        if user_input.lower() in ["exit", "quit"]:
            break
            
        run_conversation(chat_session, user_input)

if __name__ == "__main__":
    main()
