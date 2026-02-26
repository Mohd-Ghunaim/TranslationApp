from flask import Flask, request, jsonify
from flask_cors import CORS
from googletrans import Translator

app = Flask(__name__)
CORS(app)

@app.route("/translate", methods=['POST'])
def translate():
  data = request.get_json()
  text = data.get("text")
  source_lang = data.get("source")
  target_lang = data.get("target")

  translator = Translator()
  translated = translator.translate(text, src=source_lang, dest=target_lang)

  return {"translated_text": translated.text}

if __name__ == "__main__":
  app.run(debug=True)