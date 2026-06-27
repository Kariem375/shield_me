import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

# This looks inside .env file for "GOOGLE_API_KEY" and grabs the actual key
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash")

def generate_response(prompt):
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error connecting to AI: {str(e)}"