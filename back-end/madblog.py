from app import create_app
from config import Config

app = create_app(Config)


@app.route('/')
def hello_world():
    return 'Hello, World!'
