from flask_script import Manager

from app import create_app
from config import Config

app = create_app(Config)

manage = Manager(app)


@app.route('/')
def hello_world():
    return 'Hello, World!'


if __name__ == '__main__':
    manage.run()
