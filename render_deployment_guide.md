# Deploying to Render

This guide will walk you through deploying your Python web application to Render.

## 1. Prerequisites

- A Render account ([https://render.com/](https://render.com/))
- A Google Cloud Platform (GCP) project with the Gmail and Google Calendar APIs enabled.
- `credentials.json` file from your GCP project.
- A GitHub or GitLab account.

## 2. Setting up your Google Credentials

1.  **Enable APIs:** Go to the [Google Cloud Console](https://console.cloud.google.com/) and make sure you have a project created. In your project, enable the **Gmail API** and the **Google Calendar API**.
2.  **Create OAuth 2.0 Credentials:**
    *   Go to "APIs & Services" > "Credentials".
    *   Click "Create Credentials" and select "OAuth client ID".
    *   Choose "Web application" as the application type.
    *   Add `http://localhost:8080` to the "Authorized redirect URIs". You will use this for the initial authentication.
    *   Click "Create" and download the `credentials.json` file.
3.  **Place `credentials.json`:** Place the downloaded `credentials.json` file in the `Agent` directory of your project.

## 3. Preparing your Repository

1.  **Push to GitHub/GitLab:** Make sure your project, including the `requirements.txt` and `render_deployment_guide.md` files, is pushed to a GitHub or GitLab repository.
2.  **Add `credentials.json` to `.gitignore`:** To keep your credentials secure, add `Agent/credentials.json` to your `.gitignore` file. You will set the credentials as an environment variable on Render.

## 4. Deploying to Render

1.  **Create a New Web Service:**
    *   On the Render dashboard, click "New +" and select "Web Service".
    *   Connect your GitHub or GitLab account and select your repository.
2.  **Configuration:**
    *   **Name:** A name for your service (e.g., `my-ai-agent`).
    *   **Region:** A region close to you.
    *   **Branch:** The branch to deploy (e.g., `main`).
    *   **Root Directory:** Leave blank.
    *   **Runtime:** `Python 3`.
    *   **Build Command:** `pip install -r requirements.txt`.
    *   **Start Command:** `gunicorn app:app`.
3.  **Environment Variables:**
    *   Click "Add Environment Variable" for each of the following:
        *   `GROQ_API_KEY`: Your Groq API key.
        *   `GENAI_API_KEY`: Your Google Generative AI API key.
        *   `TAVILY_API_KEY`: Your Tavily API key.
        *   `CREDENTIAL_PASSWORD`: A secure, randomly generated password for encrypting your tokens.
        *   `GOOGLE_CREDENTIALS`: The content of your `Agent/credentials.json` file. You can copy and paste the entire content of the JSON file as the value.

## 5. Initial Authentication (One-time setup)

Because this application uses OAuth for Google services, you need to perform a one-time authentication step locally to generate the initial tokens.

1.  **Run Locally:** Before deploying, run the application on your local machine.
2.  **Authenticate:** The application will open a browser window for you to authenticate with your Google account.
3.  **Token Generation:** After successful authentication, encrypted token files (`calendar_token.enc` and `gmail_token.enc`) will be created in the `Agent` directory.
4.  **Commit Tokens:** Commit and push these `.enc` files to your repository. Render will use these tokens to make authenticated API calls.

## 6. Final Deployment

- After setting the environment variables, click "Create Web Service".
- Render will build and deploy your application. You can monitor the progress in the "Events" tab.
- Once deployed, your application will be available at the URL provided by Render.
