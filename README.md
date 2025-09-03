# AI Personal Assistant

This is a sophisticated AI-powered personal assistant that runs as a web application. It can help you with a variety of tasks, including web searches, managing your Google Calendar, and sending emails. The assistant is built with Python, Flask, and the Google Generative AI API.

## Features

- **Conversational AI:** Engage in natural conversations with a powerful AI model.
- **Web Search:** Get up-to-date information from the web.
- **Google Calendar Integration:**
    - Create new calendar events.
    - Search for existing events.
    - Update event details.
    - Delete events from your calendar.
- **Gmail Integration:**
    - Send emails to your contacts.
    - Read your latest emails.
    - Add labels to your emails.
- **Secure Authentication:** Uses OAuth 2.0 for secure access to your Google account data.
- **Web Interface:** A simple and intuitive web interface for interacting with the assistant.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Python 3.7+
- A Google Cloud Platform (GCP) project with the Gmail and Google Calendar APIs enabled.
- API keys for:
    - Google Generative AI
    - Groq
    - Tavily

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/your-repository-name.git
    cd your-repository-name
    ```

2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up your API keys:**
    - Rename `Agent/api_keys.py.example` to `Agent/api_keys.py`.
    - Add your API keys to the `Agent/api_keys.py` file.

5.  **Set up your Google Credentials:**
    - Follow the instructions in the [deployment guide](render_deployment_guide.md#2-setting-up-your-google-credentials) to get your `credentials.json` file.
    - Place the `credentials.json` file in the `Agent` directory.

### Running the Application

1.  **Run the Flask application:**
    ```bash
    python app.py
    ```

2.  **Open your browser:**
    - Navigate to `http://127.0.0.1:5000` in your web browser.

3.  **Authenticate with Google:**
    - The first time you use a Google-related feature, a browser window will open for you to authenticate. This will create encrypted token files in the `Agent` directory.

## Deployment

For instructions on how to deploy this application to a live server, please see the [Render Deployment Guide](render_deployment_guide.md).
